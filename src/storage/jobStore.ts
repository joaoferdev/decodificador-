import path from "node:path";

import { env } from "../config/env.js";
import { FsJobRepository } from "./fsJobRepository.js";

export const jobStore = new FsJobRepository({
  storageRoot: env.JOB_STORAGE_ROOT || path.join(process.cwd(), ".tmp", "atlas-certificate-toolkit"),
  ttlMs: env.JOB_TTL_MS
});

export const createJob = jobStore.create.bind(jobStore);
export const getJob = jobStore.get.bind(jobStore);
export const setParsed = jobStore.setParsed.bind(jobStore);
export const setAnalysis = jobStore.setAnalysis.bind(jobStore);
export const addArtifacts = jobStore.addArtifacts.bind(jobStore);
export const getArtifact = jobStore.getArtifact.bind(jobStore);
