import type { JobRepository } from "../storage/jobRepository.js";

export function getJobUseCase(repository: JobRepository, jobId: string) {
  return repository.get(jobId);
}
