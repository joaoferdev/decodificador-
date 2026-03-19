
export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const base = import.meta.env.VITE_API_BASE ?? "http://localhost:3000";

  const res = await fetch(`${base}${path}`, init);

  if (!res.ok) {
    
    const ctErr = res.headers.get("content-type") ?? "";
    if (ctErr.includes("application/json")) {
      const j = await res.json().catch(() => null);
      throw new Error(j?.message || j?.error || `HTTP ${res.status}`);
    }
    const txt = await res.text().catch(() => "");
    throw new Error(txt || `HTTP ${res.status}`);
  }

  const ct = res.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) return (await res.json()) as T;

  
  return (await res.text()) as unknown as T;
}