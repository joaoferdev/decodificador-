import { z } from "zod";

export const pemPayloadSchema = z.object({
  pem: z.string().trim().min(1)
});

const passwordField = z.string().trim().min(1);

export const extractPkcs12Schema = z.object({
  password: passwordField
});

export const buildBundleSchema = z.object({
  sourcePassword: z.string().trim().min(1).optional()
});

export const generatePkcs12Schema = z.object({
  password: passwordField
});

export const exportFormatsSchema = z.object({
  formats: z.array(z.string().trim().min(1)).min(1),
  sourcePassword: z.string().trim().min(1).optional(),
  outputPassword: z.string().trim().min(1).optional()
});

export const recipeNameSchema = z.enum([
  "build_bundle",
  "extract_pkcs12",
  "generate_pkcs12",
  "export_formats",
  "decode_csr"
]);

export type RecipeName = z.infer<typeof recipeNameSchema>;
