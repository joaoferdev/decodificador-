import type { InputFile, ParsedObject, Artifact, JobAnalysis, JobPublic } from "../domain/types.js";
import { randomId } from "../utils/crypto.js";

type InternalJob = {
  job: JobPublic;
  files: InputFile[];
  artifacts: Artifact[];
};

const store = new Map<string, InternalJob>();
const createdAt = new Map<string, number>();

const JOB_TTL_MS = 30 * 60 * 1000; // 30 minutos

export function createJob(files: InputFile[]): InternalJob {
  cleanupExpired();

  const id = randomId("job");
  const job: JobPublic = {
    id,
    createdAt: new Date().toISOString(),
    status: "created",
    inputs: files.map(({ bytes, ...rest }) => rest),
    parsed: [],
    artifacts: []
  };

  const internal: InternalJob = { job, files, artifacts: [] };
  store.set(id, internal);
  createdAt.set(id, Date.now());
  return internal;
}

export function getJob(jobId: string): InternalJob | null {
  cleanupExpired();
  return store.get(jobId) ?? null;
}

export function setParsed(jobId: string, parsed: ParsedObject[]): void {
  const internal = getJob(jobId);
  if (!internal) return;
  internal.job.parsed = parsed;
  internal.job.status = "parsed";
}


export function setAnalysis(jobId: string, analysis: JobAnalysis): void {
  const internal = getJob(jobId);
  if (!internal) return;

  internal.job.analysis = {
    ...(internal.job.analysis ?? {}),
    ...(analysis ?? {})
  };
}

export function addArtifacts(jobId: string, artifacts: Artifact[]): void {
  const internal = getJob(jobId);
  if (!internal) return;
  internal.artifacts.push(...artifacts);
  internal.job.artifacts = internal.artifacts.map(({ bytes, ...rest }) => rest);
}

export function getArtifact(jobId: string, artifactId: string): Artifact | null {
  const internal = getJob(jobId);
  if (!internal) return null;
  return internal.artifacts.find((a) => a.id === artifactId) ?? null;
}

function cleanupExpired() {
  const now = Date.now();
  for (const [id, ts] of createdAt.entries()) {
    if (now - ts > JOB_TTL_MS) {
      store.delete(id);
      createdAt.delete(id);
    }
  }
}
