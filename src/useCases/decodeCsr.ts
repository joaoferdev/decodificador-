import type { InputFile } from "../domain/types.js";
import { recipeDecodeCsr } from "../recipes/decodeCsr.js";
import { normalizeInputs } from "../services/normalizer.js";

export function decodeCsrUseCase(inputs: InputFile[]) {
  const parsed = normalizeInputs(inputs);
  const decoded = recipeDecodeCsr(inputs, parsed);
  const { warnings, ...decodedWithoutWarnings } = decoded;

  return {
    decoded: decodedWithoutWarnings,
    warnings
  };
}
