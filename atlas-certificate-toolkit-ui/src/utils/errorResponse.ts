export type ErrorBody = {
  error?: string;
  message?: string;
};

export async function extractErrorMessage(
  contentType: string | null,
  readJson: () => Promise<ErrorBody | null>,
  readText: () => Promise<string>
) {
  if ((contentType ?? "").includes("application/json")) {
    const json = await readJson().catch(() => null);
    return json?.message || json?.error || null;
  }

  const text = await readText().catch(() => "");
  return text || null;
}
