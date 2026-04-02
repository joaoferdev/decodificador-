import type { JobAnalysis } from "../domain/types.js";
import { incrementMetric } from "../lib/metrics.js";
import { recipeBuildBundle } from "../recipes/buildBundle.js";
import { recipeDecodeCsr } from "../recipes/decodeCsr.js";
import { recipeExportFormats } from "../recipes/exportFormats.js";
import { recipeExtractPkcs12 } from "../recipes/extractPkcs12.js";
import { recipeGeneratePkcs12 } from "../recipes/generatePkcs12.js";
import type { JobRepository } from "../storage/jobRepository.js";
import type { InternalJob } from "../storage/jobRepository.js";
import type { RecipeName } from "../api/schemas.js";

type RecipeResponse = Record<string, unknown>;

export function runRecipeUseCase(
  repository: JobRepository,
  jobId: string,
  internal: InternalJob,
  recipe: RecipeName,
  body: unknown
): RecipeResponse {
  incrementMetric("recipesRun");
  switch (recipe) {
    case "build_bundle": {
      const payload = body as { sourcePassword?: string };
      const artifacts = recipeBuildBundle(internal.files, internal.job.parsed, payload);
      repository.addArtifacts(jobId, artifacts);
      return { artifacts: repository.get(jobId)?.job.artifacts ?? [] };
    }
    case "extract_pkcs12": {
      const { password } = body as { password: string };
      const artifacts = recipeExtractPkcs12(internal.files, internal.job.parsed, { password });
      repository.addArtifacts(jobId, artifacts);
      return { artifacts: repository.get(jobId)?.job.artifacts ?? [] };
    }
    case "generate_pkcs12": {
      const { password } = body as { password: string };
      const artifact = recipeGeneratePkcs12(internal.files, internal.job.parsed, { password });
      repository.addArtifacts(jobId, [artifact]);
      return { artifacts: repository.get(jobId)?.job.artifacts ?? [] };
    }
    case "export_formats": {
      const payload = body as { formats: string[]; sourcePassword?: string; outputPassword?: string };
      const artifacts = recipeExportFormats(internal.files, internal.job.parsed, payload);
      repository.addArtifacts(jobId, artifacts);
      return { artifacts: repository.get(jobId)?.job.artifacts ?? [] };
    }
    case "decode_csr": {
      const decoded = recipeDecodeCsr(internal.files, internal.job.parsed);
      const analysis: JobAnalysis = {
        decodedCsr: decoded,
        warnings: decoded.warnings ?? []
      };
      repository.setAnalysis(jobId, analysis);
      return { decoded, analysis: repository.get(jobId)?.job.analysis ?? null };
    }
  }
}
