export function formatExpiration(expiresAt: string | undefined, now = Date.now()) {
  if (!expiresAt) return "Expiracao indisponivel.";
  const expiresAtMs = Date.parse(expiresAt);
  if (Number.isNaN(expiresAtMs)) return "Expiracao indisponivel.";

  const remainingMs = expiresAtMs - now;
  if (remainingMs <= 0) return "Arquivos expirados.";

  const totalMinutes = Math.ceil(remainingMs / 60_000);
  if (totalMinutes < 60) {
    return `Expira em cerca de ${totalMinutes} min.`;
  }

  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return minutes > 0 ? `Expira em cerca de ${hours}h ${minutes}min.` : `Expira em cerca de ${hours}h.`;
}
