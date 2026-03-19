import { useMemo, useState } from "react";
import type { DecodedCsr, Warning } from "../../api/toolkit";

function safeStr(v: any) {
  if (v === null || v === undefined) return "—";
  if (Array.isArray(v)) return v.filter(Boolean).join(", ");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function copyToClipboard(text: string) {
  try {
    navigator.clipboard?.writeText(text);
  } catch {
    // ignore
  }
}

function Section(props: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <div className="csrSection">
      <div className="csrSectionHeader">
        <div className="csrSectionTitle">{props.title}</div>
        {props.subtitle ? <div className="csrSectionHint">{props.subtitle}</div> : null}
      </div>
      <div className="csrSectionBody">{props.children}</div>
    </div>
  );
}

function KVRow(props: {
  label: string;
  value: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="csrKVRow">
      <div className="csrKVLabel">{props.label}</div>
      <div className="csrKVValue">{props.value}</div>
      <div className="csrKVActions">{props.actions}</div>
    </div>
  );
}

function Pills(props: { items: string[] }) {
  if (!props.items.length) return <span className="csrMuted">—</span>;
  return (
    <div className="csrPills">
      {props.items.map((x, i) => (
        <span className="csrTag" key={`${x}-${i}`}>
          {x}
        </span>
      ))}
    </div>
  );
}

export function CsrResult(props: { decoded: DecodedCsr; warnings: Warning[] }) {
  const d = props.decoded as any;

  // ======= Tentativas de leitura (bem tolerante) =======
  const subjectObj = d.subject ?? d.subjectRdn ?? d.identification?.subject ?? d.decoded?.subject ?? {};
  const fullSubject =
    d.fullSubject ??
    d.subjectString ??
    d.subject?.full ??
    d.identification?.fullSubject ??
    d.identification?.subjectString ??
    "";

  const cn =
    subjectObj.commonName ??
    subjectObj.CN ??
    d.cn ??
    d.commonName ??
    d.subject?.CN ??
    "";

  const o = subjectObj.organization ?? subjectObj.O ?? d.organization ?? d.subject?.O ?? "";
  const ou =
    subjectObj.organizationalUnit ?? subjectObj.OU ?? d.organizationalUnit ?? d.subject?.OU ?? "";
  const l = subjectObj.locality ?? subjectObj.L ?? d.locality ?? d.subject?.L ?? "";
  const st = subjectObj.state ?? subjectObj.ST ?? d.state ?? d.subject?.ST ?? "";
  const c = subjectObj.country ?? subjectObj.C ?? d.country ?? d.subject?.C ?? "";
  const email = subjectObj.email ?? subjectObj.E ?? d.email ?? d.subject?.E ?? "";

  const sigAlg =
    d.signatureAlgorithm ??
    d.signatureAlg ??
    d.signature?.algorithm ??
    d.signature?.alg ??
    "";

  const keyBits =
    d.keyBits ??
    d.publicKeyBits ??
    d.key?.bits ??
    d.publicKey?.bits ??
    d.publicKeyInfo?.bits ??
    "";

  const keyType =
    d.keyType ??
    d.publicKeyType ??
    d.key?.type ??
    d.publicKey?.type ??
    d.publicKeyInfo?.type ??
    "";

  const sanDns: string[] = useMemo(() => {
    const ext = d.extensions ?? {};
    const san =
      ext.subjectAltName ??
      ext.san ??
      d.san ??
      d.subjectAltName ??
      d.altNames ??
      {};

    const dns =
      san.dns ??
      san.DNS ??
      san.dnsNames ??
      san.dns_names ??
      san.names ??
      [];

    if (Array.isArray(dns)) return dns.map(String).filter(Boolean);
    if (typeof dns === "string") return [dns];
    return [];
  }, [d]);

  const fpSha1 =
    d.fingerprints?.sha1 ??
    d.fingerprint?.sha1 ??
    d.sha1 ??
    d.hashes?.sha1 ??
    "";

  const fpSha256 =
    d.fingerprints?.sha256 ??
    d.fingerprint?.sha256 ??
    d.sha256 ??
    d.hashes?.sha256 ??
    "";

  const [showFullSubject, setShowFullSubject] = useState(false);
  const [showSha1, setShowSha1] = useState(false);
  const [showSha256, setShowSha256] = useState(false);

  return (
    <div className="csrResultPro">
      {/* Top summary pills */}
      <div className="csrTopPills">
        <span className="csrTopPill">
          <span className="k">Assinatura</span>
          <span className="v">{sigAlg ? safeStr(sigAlg) : "—"}</span>
        </span>
        <span className="csrTopPill">
          <span className="k">Chave</span>
          <span className="v">
            {keyType ? String(keyType).toUpperCase() : "—"}
            {keyBits ? ` • ${safeStr(keyBits)} bits` : ""}
          </span>
        </span>
        <span className="csrTopPill">
          <span className="k">SAN (DNS)</span>
          <span className="v">{sanDns.length ? `${sanDns.length} nome(s)` : "—"}</span>
        </span>
      </div>

      <Section title="Common Name (CN)" subtitle="Nome comum (CN)">
        <KVRow
          label="CN"
          value={<span className="csrMono">{cn ? safeStr(cn) : "—"}</span>}
          actions={
            cn ? (
              <button className="btn ghost" onClick={() => copyToClipboard(String(cn))}>
                Copiar
              </button>
            ) : null
          }
        />
      </Section>

      <Section title="Identificação" subtitle="Subject">
        <KVRow label="Organização (O)" value={<span className="csrMono">{safeStr(o)}</span>} />
        <KVRow label="Unidade (OU)" value={<span className="csrMono">{safeStr(ou)}</span>} />
        <KVRow label="Cidade (L)" value={<span className="csrMono">{safeStr(l)}</span>} />
        <KVRow label="Estado (ST)" value={<span className="csrMono">{safeStr(st)}</span>} />
        <KVRow label="País (C)" value={<span className="csrMono">{safeStr(c)}</span>} />
        <KVRow label="E-mail (E)" value={<span className="csrMono">{safeStr(email)}</span>} />

        <div className="csrDividerSoft" />

        <KVRow
          label="Subject completo"
          value={
            <span className="csrMono">
              {fullSubject
                ? showFullSubject
                  ? safeStr(fullSubject)
                  : `${String(fullSubject).slice(0, 80)}${String(fullSubject).length > 80 ? "…" : ""}`
                : "—"}
            </span>
          }
          actions={
            fullSubject ? (
              <>
                <button className="btn ghost" onClick={() => setShowFullSubject((s) => !s)}>
                  {showFullSubject ? "Ocultar" : "Ver completo"}
                </button>
                <button className="btn ghost" onClick={() => copyToClipboard(String(fullSubject))}>
                  Copiar
                </button>
              </>
            ) : null
          }
        />
      </Section>

      <Section title="Impressões digitais" subtitle="Fingerprints">
        <KVRow
          label="SHA-1"
          value={
            <span className="csrMono">
              {fpSha1
                ? showSha1
                  ? safeStr(fpSha1)
                  : `${String(fpSha1).slice(0, 22)}…${String(fpSha1).slice(-10)}`
                : "—"}
            </span>
          }
          actions={
            fpSha1 ? (
              <>
                <button className="btn ghost" onClick={() => setShowSha1((s) => !s)}>
                  {showSha1 ? "Ocultar" : "Ver completo"}
                </button>
                <button className="btn ghost" onClick={() => copyToClipboard(String(fpSha1))}>
                  Copiar
                </button>
              </>
            ) : null
          }
        />

        <KVRow
          label="SHA-256"
          value={
            <span className="csrMono">
              {fpSha256
                ? showSha256
                  ? safeStr(fpSha256)
                  : `${String(fpSha256).slice(0, 22)}…${String(fpSha256).slice(-10)}`
                : "—"}
            </span>
          }
          actions={
            fpSha256 ? (
              <>
                <button className="btn ghost" onClick={() => setShowSha256((s) => !s)}>
                  {showSha256 ? "Ocultar" : "Ver completo"}
                </button>
                <button className="btn ghost" onClick={() => copyToClipboard(String(fpSha256))}>
                  Copiar
                </button>
              </>
            ) : null
          }
        />
      </Section>

      <Section title="Extensões" subtitle="Extensions">
        <KVRow
          label="SAN (DNS)"
          value={<Pills items={sanDns} />}
          actions={
            sanDns.length ? (
              <button className="btn ghost" onClick={() => copyToClipboard(sanDns.join("\n"))}>
                Copiar
              </button>
            ) : null
          }
        />
      </Section>

      {props.warnings?.length ? (
        <Section title="Avisos" subtitle="Warnings">
          <div className="csrWarnings">
            {props.warnings.map((w, i) => (
              <div className="csrWarn" key={`${w.code}-${i}`}>
                <div className="csrWarnCode">{w.code}</div>
                <div className="csrWarnMsg">{w.message}</div>
              </div>
            ))}
          </div>
        </Section>
      ) : null}
    </div>
  );
}