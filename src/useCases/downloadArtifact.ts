import { incrementMetric } from "../lib/metrics.js";
import type { JobRepository } from "../storage/jobRepository.js";

export function downloadArtifactUseCase(repository: JobRepository, jobId: string, artifactId: string) {
  const artifact = repository.getArtifact(jobId, artifactId);
  if (artifact) incrementMetric("artifactsDownloaded");
  return artifact;
}
