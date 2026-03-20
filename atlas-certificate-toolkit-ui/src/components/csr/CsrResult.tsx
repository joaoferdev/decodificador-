import { useMemo, useState, type ReactNode } from "react";
import type { DecodedCsr, Warning } from "../../api/toolkit";

type UnknownRecord = Record<string, unknown>;

function asRecord(value: unknown): UnknownRecord {
  return value !== null && typeof value === "object" ? (value as UnknownRecord) : {};
}

function safeStr(v: unknown) {
  if (v === null || v === undefined) return "—";
  if (Array.isArray(v)) return v.filter(Boolean).join(", ");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function formatDistinguishedName(value: string): string[] {
  return value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

function copyToClipboard(text: string) {
  try {
    navigator.clipboard?.writeText(text);
  } catch {
    // ignore
  }
}

function Section(props: { title: string; subtitle?: string; children: ReactNode }) {
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
  value: ReactNode;
  actions?: ReactNode;
  className?: string;
}) {
  return (
    <div className={`csrKVRow${props.className ? ` ${props.className}` : ""}`}>
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
  const d = props.decoded;
  const subjectObj = asRecord(d.subject);
  const sigRecord = asRecord(d.signature);
  const pubKeyRecord = asRecord(d.publicKey);
  const fingerprints = asRecord(d.fingerprints);

  const fullSubject = d.subjectString ?? "";
  const cn = subjectObj.commonName ?? subjectObj.CN ?? "";
  const o = subjectObj.organization ?? subjectObj.O ?? "";
  const ou = subjectObj.organizationalUnit ?? subjectObj.OU ?? "";
  const l = subjectObj.locality ?? subjectObj.L ?? "";
  const st = subjectObj.state ?? subjectObj.ST ?? "";
  const c = subjectObj.country ?? subjectObj.C ?? "";
  const email = subjectObj.email ?? subjectObj.E ?? "";

  const sigAlg = sigRecord.algorithm ?? "";
  const keyBits = pubKeyRecord.bits ?? "";
  const keyType = pubKeyRecord.algorithm ?? "";

  const sanDns: string[] = useMemo(() => {
    const ext = asRecord(d.extensions);
    const san = asRecord(ext.subjectAltName);
    const dns = san.dns ?? san.DNS ?? san.dnsNames ?? san.dns_names ?? san.names ?? [];

    if (Array.isArray(dns)) return dns.map(String).filter(Boolean);
    if (typeof dns === "string") return [dns];
    return [];
  }, [d.extensions]);

  const fpSha1 = fingerprints.sha1 ?? "";
  const fpSha256 = fingerprints.sha256 ?? "";
  const formattedSubject = useMemo(
    () => (fullSubject ? formatDistinguishedName(String(fullSubject)) : []),
    [fullSubject]
  );

  const [showFullSubject, setShowFullSubject] = useState(false);
  const [showSha1, setShowSha1] = useState(false);
  const [showSha256, setShowSha256] = useState(false);

  return (
    <div className="csrResultPro">
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

      <Section title="Identificacao" subtitle="Subject">
        <KVRow label="Organizacao (O)" value={<span className="csrMono">{safeStr(o)}</span>} />
        <KVRow label="Unidade (OU)" value={<span className="csrMono">{safeStr(ou)}</span>} />
        <KVRow label="Cidade (L)" value={<span className="csrMono">{safeStr(l)}</span>} />
        <KVRow label="Estado (ST)" value={<span className="csrMono">{safeStr(st)}</span>} />
        <KVRow label="Pais (C)" value={<span className="csrMono">{safeStr(c)}</span>} />
        <KVRow label="E-mail (E)" value={<span className="csrMono">{safeStr(email)}</span>} />

        <div className="csrDividerSoft" />

        <KVRow
          label="Subject completo"
          className="csrKVRowExpanded"
          value={
            <div className="csrSubjectBlock">
              {fullSubject
                ? showFullSubject
                  ? formattedSubject.map((part, index) => (
                      <div className="csrSubjectLine csrMono" key={`${part}-${index}`}>
                        {part}
                      </div>
                    ))
                  : `${String(fullSubject).slice(0, 80)}${String(fullSubject).length > 80 ? "..." : ""}`
                : "—"}
            </div>
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

      <Section title="Impressoes digitais" subtitle="Fingerprints">
        <KVRow
          label="SHA-1"
          value={
            <span className="csrMono">
              {fpSha1
                ? showSha1
                  ? safeStr(fpSha1)
                  : `${String(fpSha1).slice(0, 22)}...${String(fpSha1).slice(-10)}`
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
                  : `${String(fpSha256).slice(0, 22)}...${String(fpSha256).slice(-10)}`
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

      <Section title="Extensoes" subtitle="Extensions">
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

      {props.warnings.length ? (
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
