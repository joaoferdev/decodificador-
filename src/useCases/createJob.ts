import type { InputFile } from "../domain/types.js";
import { incrementMetric } from "../lib/metrics.js";
import type { JobRepository } from "../storage/jobRepository.js";
import { analyze } from "../services/analyzer.js";
import { normalizeInputs } from "../services/normalizer.js";

export function createJobUseCase(repository: JobRepository, files: InputFile[]) {
  const internal = repository.create(files);
  incrementMetric("jobsCreated");
  const parsed = normalizeInputs(internal.files);
  repository.setParsed(internal.job.id, parsed);
  repository.setAnalysis(internal.job.id, analyze(internal.files, parsed));
  return repository.get(internal.job.id) ?? internal;
}
