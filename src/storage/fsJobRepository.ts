import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import type { Artifact, InputFile, JobAnalysis, JobPublic, ParsedObject } from "../domain/types.js";
import { incrementMetric } from "../lib/metrics.js";
import type { InternalJob, JobRepository } from "./jobRepository.js";
import { logger } from "../lib/logger.js";

type StoredInput = Omit<InputFile, "bytes"> & { diskPath: string };
type StoredArtifact = Omit<Artifact, "bytes"> & { diskPath: string };
type JobMetadata = { id: string; createdAtMs: number; expiresAtMs: number };

type StoredJob = {
  dir: string;
  createdAtMs: number;
  expiresAtMs: number;
  job: JobPublic;
  inputs: StoredInput[];
  artifacts: StoredArtifact[];
};

type FsJobRepositoryOptions = {
  storageRoot: string;
  ttlMs: number;
};

const METADATA_FILENAME = "job-meta.json";

export class FsJobRepository implements JobRepository {
  private readonly store = new Map<string, StoredJob>();
  private readonly storageRoot: string;
  private readonly ttlMs: number;

  constructor(options: FsJobRepositoryOptions) {
    this.storageRoot = options.storageRoot;
    this.ttlMs = options.ttlMs;
    fs.mkdirSync(this.storageRoot, { recursive: true });
    this.cleanupExpiredDirectoriesOnStartup();
    const timer = setInterval(() => this.cleanupExpired(), 60_000);
    timer.unref();
  }

  create(files: InputFile[]): InternalJob {
    this.cleanupExpired();

    const id = `job_${crypto.randomUUID()}`;
    const dir = path.join(this.storageRoot, id);
    const inputsDir = path.join(dir, "inputs");
    const artifactsDir = path.join(dir, "artifacts");
    const createdAtMs = Date.now();
    const expiresAtMs = createdAtMs + this.ttlMs;
    this.ensureDir(inputsDir);
    this.ensureDir(artifactsDir);

    const job: JobPublic = {
      id,
      createdAt: new Date(createdAtMs).toISOString(),
      expiresAt: new Date(expiresAtMs).toISOString(),
      status: "created",
      inputs: files.map(({ bytes, ...rest }) => rest),
      parsed: [],
      artifacts: []
    };

    const inputs: StoredInput[] = files.map(({ bytes, ...rest }) => {
      const diskPath = path.join(inputsDir, `${rest.id}.bin`);
      fs.writeFileSync(diskPath, bytes);
      return { ...rest, diskPath };
    });

    const stored: StoredJob = {
      dir,
      createdAtMs,
      expiresAtMs,
      job,
      inputs,
      artifacts: []
    };

    this.writeMetadata(stored);
    this.store.set(id, stored);
    return this.toInternalJob(stored);
  }

  get(jobId: string): InternalJob | null {
    this.cleanupExpired();
    const stored = this.store.get(jobId);
    return stored ? this.toInternalJob(stored) : null;
  }

  setParsed(jobId: string, parsed: ParsedObject[]): void {
    this.cleanupExpired();
    const stored = this.store.get(jobId);
    if (!stored) return;
    stored.job.parsed = parsed;
    stored.job.status = "parsed";
  }

  setAnalysis(jobId: string, analysis: JobAnalysis): void {
    this.cleanupExpired();
    const stored = this.store.get(jobId);
    if (!stored) return;
    stored.job.analysis = {
      ...(stored.job.analysis ?? {}),
      ...(analysis ?? {})
    };
  }

  addArtifacts(jobId: string, artifacts: Artifact[]): void {
    this.cleanupExpired();
    const stored = this.store.get(jobId);
    if (!stored) return;

    const artifactsDir = path.join(stored.dir, "artifacts");
    this.ensureDir(artifactsDir);

    for (const artifact of artifacts) {
      const duplicate = stored.artifacts.find(
        (item) => item.filename === artifact.filename && item.sha256 === artifact.sha256
      );
      if (duplicate) continue;

      const diskPath = path.join(artifactsDir, `${artifact.id}.bin`);
      fs.writeFileSync(diskPath, artifact.bytes);
      stored.artifacts.push({
        id: artifact.id,
        filename: artifact.filename,
        mimeType: artifact.mimeType,
        size: artifact.size,
        sha256: artifact.sha256,
        diskPath
      });
    }

    stored.job.artifacts = stored.artifacts.map(({ diskPath, ...rest }) => rest);
  }

  getArtifact(jobId: string, artifactId: string): Artifact | null {
    this.cleanupExpired();
    const stored = this.store.get(jobId);
    if (!stored) return null;
    const artifact = stored.artifacts.find((item) => item.id === artifactId);
    return artifact ? this.hydrateArtifact(artifact) : null;
  }

  private ensureDir(dirPath: string) {
    fs.mkdirSync(dirPath, { recursive: true });
  }

  private metadataPath(dirPath: string) {
    return path.join(dirPath, METADATA_FILENAME);
  }

  private writeMetadata(stored: StoredJob) {
    const metadata: JobMetadata = {
      id: stored.job.id,
      createdAtMs: stored.createdAtMs,
      expiresAtMs: stored.expiresAtMs
    };

    fs.writeFileSync(this.metadataPath(stored.dir), JSON.stringify(metadata, null, 2), "utf8");
  }

  private readMetadata(dirPath: string): JobMetadata | null {
    try {
      const raw = fs.readFileSync(this.metadataPath(dirPath), "utf8");
      const parsed = JSON.parse(raw) as Partial<JobMetadata>;
      if (
        typeof parsed.id === "string" &&
        typeof parsed.createdAtMs === "number" &&
        typeof parsed.expiresAtMs === "number"
      ) {
        return {
          id: parsed.id,
          createdAtMs: parsed.createdAtMs,
          expiresAtMs: parsed.expiresAtMs
        };
      }
    } catch {
      // no-op
    }

    return null;
  }

  private removeJobDirectory(dirPath: string) {
    fs.rmSync(dirPath, { recursive: true, force: true });
  }

  private cleanupExpiredDirectoriesOnStartup() {
    const now = Date.now();
    let removed = 0;

    for (const entry of fs.readdirSync(this.storageRoot, { withFileTypes: true })) {
      if (!entry.isDirectory() || !entry.name.startsWith("job_")) continue;
      const dirPath = path.join(this.storageRoot, entry.name);
      const metadata = this.readMetadata(dirPath);
      const expiresAtMs =
        metadata?.expiresAtMs ??
        (() => {
          try {
            return fs.statSync(dirPath).mtimeMs + this.ttlMs;
          } catch {
            return now - 1;
          }
        })();

      if (expiresAtMs <= now) {
        this.removeJobDirectory(dirPath);
        incrementMetric("jobsExpired");
        removed++;
      }
    }

    if (removed > 0) {
      logger.info({ removed, storageRoot: this.storageRoot }, "Expired toolkit job directories removed on startup");
    }
  }

  private hydrateInput(file: StoredInput): InputFile {
    return {
      id: file.id,
      originalName: file.originalName,
      mimeType: file.mimeType,
      size: file.size,
      sha256: file.sha256,
      bytes: fs.readFileSync(file.diskPath)
    };
  }

  private hydrateArtifact(artifact: StoredArtifact): Artifact {
    return {
      id: artifact.id,
      filename: artifact.filename,
      mimeType: artifact.mimeType,
      size: artifact.size,
      sha256: artifact.sha256,
      bytes: fs.readFileSync(artifact.diskPath)
    };
  }

  private toInternalJob(stored: StoredJob): InternalJob {
    return {
      job: {
        ...stored.job,
        artifacts: stored.artifacts.map(({ diskPath, ...rest }) => rest)
      },
      files: stored.inputs.map((file) => this.hydrateInput(file)),
      artifacts: stored.artifacts.map((artifact) => this.hydrateArtifact(artifact))
    };
  }

  private cleanupExpired() {
    const now = Date.now();
    for (const [id, stored] of this.store.entries()) {
      if (stored.expiresAtMs <= now) {
        this.removeJobDirectory(stored.dir);
        this.store.delete(id);
        incrementMetric("jobsExpired");
      }
    }
  }
}
