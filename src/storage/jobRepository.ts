import type { Artifact, InputFile, JobAnalysis, JobPublic, ParsedObject } from "../domain/types.js";

export type InternalJob = {
  job: JobPublic;
  files: InputFile[];
  artifacts: Artifact[];
};

export interface JobRepository {
  create(files: InputFile[]): InternalJob;
  get(jobId: string): InternalJob | null;
  setParsed(jobId: string, parsed: ParsedObject[]): void;
  setAnalysis(jobId: string, analysis: JobAnalysis): void;
  addArtifacts(jobId: string, artifacts: Artifact[]): void;
  getArtifact(jobId: string, artifactId: string): Artifact | null;
}
