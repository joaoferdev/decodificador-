console.log("ROUTES carregadas (jobs + recipes + csr/decode one-shot)");

import { Router } from "express";
import multer from "multer";

import { sha256Hex, randomId } from "../utils/crypto.js";
import { ToolkitException } from "../utils/errors.js";

import {
  createJob,
  getJob,
  setParsed,
  setAnalysis,
  addArtifacts,
  getArtifact
} from "../storage/jobStore.js";

import { normalizeInputs } from "../services/normalizer.js";
import { analyze } from "../services/analyzer.js";

import { recipeBuildBundle } from "../recipes/buildBundle.js";
import { recipeExportFormats } from "../recipes/exportFormats.js";
import { recipeExtractPkcs12 } from "../recipes/extractPkcs12.js";
import { recipeGeneratePkcs12 } from "../recipes/generatePkcs12.js";
import { recipeDecodeCsr } from "../recipes/decodeCsr.js";

export const routes = Router();

// upload em memória
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { files: 10, fileSize: 10 * 1024 * 1024 }
});

routes.get("/toolkit/ping", (_req, res) => res.json({ pong: true }));


routes.post("/toolkit/csr/decode", (req, res, next) => {
  // Se for multipart, aplica multer. Se não for, segue sem multer.
  const isMultipart = req.headers["content-type"]?.includes("multipart/form-data");
  if (isMultipart) return upload.array("files")(req as any, res as any, next);
  return next();
}, (req, res) => {
  try {
    // 1) JSON { pem: "..." }
    const pemFromJson =
      typeof (req.body as any)?.pem === "string" ? String((req.body as any).pem) : "";

    // 2) text/plain com PEM puro
    const pemFromText =
      typeof req.body === "string" ? String(req.body) : "";

    // 3) multipart file(s)
    const files = ((req.files as Express.Multer.File[]) ?? []);

    // decide qual PEM usar (prioridade: json -> text -> files)
    const pemPicked =
      pemFromJson.trim().length > 0
        ? pemFromJson
        : (pemFromText.trim().length > 0 ? pemFromText : "");

    // monta InputFile[] unificado
    const inputs =
      pemPicked.trim().length > 0
        ? [
            {
              id: randomId("in"),
              originalName: "pasted.csr.pem",
              mimeType: "application/x-pem-file",
              size: Buffer.byteLength(pemPicked, "utf8"),
              sha256: sha256Hex(Buffer.from(pemPicked, "utf8")),
              bytes: Buffer.from(pemPicked, "utf8")
            }
          ]
        : files.map((f) => ({
            id: randomId("in"),
            originalName: f.originalname,
            mimeType: f.mimetype,
            size: f.size,
            sha256: sha256Hex(f.buffer),
            bytes: f.buffer
          }));

    if (!inputs.length) {
      return res.status(400).json({
        error: "BAD_REQUEST",
        message: "Envie um arquivo em files[] OU envie JSON { pem: '...CSR...' } OU envie text/plain com o PEM."
      });
    }

    // normaliza + decodifica
    const parsed = normalizeInputs(inputs);
    const decoded = recipeDecodeCsr(inputs, parsed);
    const { warnings, ...decodedNoWarnings } = decoded as any;

    return res.json({
      decoded: decodedNoWarnings,
      warnings: warnings ?? []
    });
  } catch (e: any) {
    if (e instanceof ToolkitException) {
      return res.status(e.httpStatus).json({ error: e.code, message: e.message });
    }
    const msg = e?.message ? String(e.message) : "Erro interno.";
    return res.status(500).json({ error: "INTERNAL_ERROR", message: msg });
  }
});

routes.post("/toolkit/jobs", upload.array("files"), (req, res) => {
  const files = (req.files as Express.Multer.File[]) ?? [];
  if (!files.length) return res.status(400).json({ error: "Envie ao menos 1 arquivo em files[]" });

  const inputs = files.map((f) => ({
    id: randomId("in"),
    originalName: f.originalname,
    mimeType: f.mimetype,
    size: f.size,
    sha256: sha256Hex(f.buffer),
    bytes: f.buffer
  }));

  const internal = createJob(inputs);

  const parsed = normalizeInputs(internal.files);
  setParsed(internal.job.id, parsed);

  const analysis = analyze(parsed);
  setAnalysis(internal.job.id, analysis);

  return res.json({ jobId: internal.job.id });
});

routes.get("/toolkit/jobs/:jobId", (req, res) => {
  const internal = getJob(req.params.jobId);
  if (!internal) return res.status(404).json({ error: "Job não encontrado (ou expirado)." });
  return res.json(internal.job);
});

routes.post("/toolkit/jobs/:jobId/recipes/:recipe", (req, res) => {
  const jobId = req.params.jobId;
  const recipe = String(req.params.recipe ?? "").trim().toLowerCase();

  const internal = getJob(jobId);
  if (!internal) return res.status(404).json({ error: "Job não encontrado (ou expirado)." });

  try {
    if (recipe === "build_bundle") {
      const art = recipeBuildBundle(internal.files, internal.job.parsed);
      addArtifacts(jobId, [art]);
      return res.json({ artifacts: getJob(jobId)?.job.artifacts ?? [] });
    }

    if (recipe === "extract_pkcs12") {
      const { password } = req.body ?? {};
      const arts = recipeExtractPkcs12(internal.files, internal.job.parsed, { password });
      addArtifacts(jobId, arts);
      return res.json({ artifacts: getJob(jobId)?.job.artifacts ?? [] });
    }

    if (recipe === "generate_pkcs12") {
      const { password } = req.body ?? {};
      const art = recipeGeneratePkcs12(internal.files, internal.job.parsed, { password });
      addArtifacts(jobId, [art]);
      return res.json({ artifacts: getJob(jobId)?.job.artifacts ?? [] });
    }

    if (recipe === "export_formats") {
      const { formats, sourcePassword, outputPassword } = req.body ?? {};
      const arts = recipeExportFormats(internal.files, internal.job.parsed, {
        formats: Array.isArray(formats) ? formats : [],
        sourcePassword,
        outputPassword
      });
      addArtifacts(jobId, arts);
      return res.json({ artifacts: getJob(jobId)?.job.artifacts ?? [] });
    }

    if (recipe === "decode_csr") {
      const decoded = recipeDecodeCsr(internal.files, internal.job.parsed);

      // salva no analysis do job
      setAnalysis(jobId, {
        decodedCsr: decoded,
        warnings: decoded.warnings ?? []
      });

      const updated = getJob(jobId);
      return res.json({ decoded, analysis: updated?.job.analysis ?? null });
    }

    return res
      .status(400)
      .json({ error: "Recipe inválida. Use build_bundle | extract_pkcs12 | generate_pkcs12 | export_formats | decode_csr" });
  } catch (e: any) {
    if (e instanceof ToolkitException) {
      return res.status(e.httpStatus).json({ error: e.code, message: e.message });
    }

    console.error("RECIPE_ERROR", { recipe, jobId, err: e });
    const msg = e?.message ? String(e.message) : "Erro interno.";
    return res.status(500).json({ error: "INTERNAL_ERROR", message: msg });
  }
});

routes.get("/toolkit/jobs/:jobId/download/:artifactId", (req, res) => {
  const { jobId, artifactId } = req.params;

  const artifact = getArtifact(jobId, artifactId);
  if (!artifact) return res.status(404).json({ error: "Artifact não encontrado." });

  res.setHeader("Content-Type", artifact.mimeType || "application/octet-stream");
  res.setHeader("Content-Disposition", `attachment; filename="${artifact.filename}"`);
  res.setHeader("Content-Length", String(artifact.bytes.length));
  res.setHeader("Cache-Control", "no-store");

  return res.status(200).send(artifact.bytes);
});
