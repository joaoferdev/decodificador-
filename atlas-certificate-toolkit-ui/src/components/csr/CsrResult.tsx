import { useMemo, useState, type ReactNode } from "react";
import type { DecodedCsr, Warning } from "../../api/toolkit";

type UnknownRecord = Record<string, unknown>;

function asRecord(value: unknown): UnknownRecord {
  return value !== null && typeof value === "object" ? (value as UnknownRecord) : {};
}

function safeStr(value: unknown) {
  if (value === null || value === undefined) return "--";
  if (Array.isArray(value)) return value.filter(Boolean).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
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

function KVRow(props: { label: string; value: ReactNode; actions?: ReactNode; className?: string }) {
  return (
    <div className={`csrKVRow${props.className ? ` ${props.className}` : ""}`}>
      <div className="csrKVLabel">{props.label}</div>
      <div className="csrKVValue">{props.value}</div>
      <div className="csrKVActions">{props.actions}</div>
    </div>
  );
}

function Pills(props: { items: string[] }) {
  if (props.items.length === 0) return <span className="csrMuted">--</span>;
  return (
    <div className="csrPills">
      {props.items.map((item, index) => (
        <span className="csrTag" key={`${item}-${index}`}>
          {item}
        </span>
      ))}
    </div>
  );
}

export function CsrResult(props: { decoded: DecodedCsr; warnings: Warning[] }) {
  const decoded = props.decoded;
  const subjectObj = asRecord(decoded.subject);
  const sigRecord = asRecord(decoded.signature);
  const pubKeyRecord = asRecord(decoded.publicKey);
  const fingerprints = asRecord(decoded.fingerprints);
  const fullSubject = decoded.subjectString ?? "";
  const cn = subjectObj.commonName ?? subjectObj.CN ?? "";
  const org = subjectObj.organization ?? subjectObj.O ?? "";
  const ou = subjectObj.organizationalUnit ?? subjectObj.OU ?? "";
  const city = subjectObj.locality ?? subjectObj.L ?? "";
  const state = subjectObj.state ?? subjectObj.ST ?? "";
  const country = subjectObj.country ?? subjectObj.C ?? "";
  const email = subjectObj.email ?? subjectObj.E ?? "";
  const sigAlg = sigRecord.algorithm ?? "";
  const keyBits = pubKeyRecord.bits ?? "";
  const keyType = pubKeyRecord.algorithm ?? "";

  const sanDns: string[] = useMemo(() => {
    const extensions = asRecord(decoded.extensions);
    const san = asRecord(extensions.subjectAltName);
    const dns = san.dns ?? san.DNS ?? san.dnsNames ?? san.dns_names ?? san.names ?? [];
    if (Array.isArray(dns)) return dns.map(String).filter(Boolean);
    if (typeof dns === "string") return [dns];
    return [];
  }, [decoded.extensions]);

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
          <span className="v">{sigAlg ? safeStr(sigAlg) : "--"}</span>
        </span>
        <span className="csrTopPill">
          <span className="k">Chave</span>
          <span className="v">
            {keyType ? String(keyType).toUpperCase() : "--"}
            {keyBits ? ` | ${safeStr(keyBits)} bits` : ""}
          </span>
        </span>
        <span className="csrTopPill">
          <span className="k">SAN (DNS)</span>
          <span className="v">{sanDns.length ? `${sanDns.length} nome(s)` : "--"}</span>
        </span>
      </div>

      <Section title="Common Name (CN)" subtitle="Nome comum (CN)">
        <KVRow
          label="CN"
          value={<span className="csrMono">{cn ? safeStr(cn) : "--"}</span>}
          actions={
            cn ? (
              <button className="btn ghost" onClick={() => copyToClipboard(String(cn))} type="button">
                Copiar
              </button>
            ) : null
          }
        />
      </Section>

      <Section title="Identificacao" subtitle="Subject">
        <KVRow label="Organizacao (O)" value={<span className="csrMono">{safeStr(org)}</span>} />
        <KVRow label="Unidade (OU)" value={<span className="csrMono">{safeStr(ou)}</span>} />
        <KVRow label="Cidade (L)" value={<span className="csrMono">{safeStr(city)}</span>} />
        <KVRow label="Estado (ST)" value={<span className="csrMono">{safeStr(state)}</span>} />
        <KVRow label="Pais (C)" value={<span className="csrMono">{safeStr(country)}</span>} />
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
                : "--"}
            </div>
          }
          actions={
            fullSubject ? (
              <>
                <button className="btn ghost" onClick={() => setShowFullSubject((state) => !state)} type="button">
                  {showFullSubject ? "Ocultar" : "Ver completo"}
                </button>
                <button className="btn ghost" onClick={() => copyToClipboard(String(fullSubject))} type="button">
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
                : "--"}
            </span>
          }
          actions={
            fpSha1 ? (
              <>
                <button className="btn ghost" onClick={() => setShowSha1((state) => !state)} type="button">
                  {showSha1 ? "Ocultar" : "Ver completo"}
                </button>
                <button className="btn ghost" onClick={() => copyToClipboard(String(fpSha1))} type="button">
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
                : "--"}
            </span>
          }
          actions={
            fpSha256 ? (
              <>
                <button className="btn ghost" onClick={() => setShowSha256((state) => !state)} type="button">
                  {showSha256 ? "Ocultar" : "Ver completo"}
                </button>
                <button className="btn ghost" onClick={() => copyToClipboard(String(fpSha256))} type="button">
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
            sanDns.length > 0 ? (
              <button className="btn ghost" onClick={() => copyToClipboard(sanDns.join("\n"))} type="button">
                Copiar
              </button>
            ) : null
          }
        />
      </Section>

      {props.warnings.length > 0 ? (
        <Section title="Avisos" subtitle="Warnings">
          <div className="csrWarnings">
            {props.warnings.map((warning, index) => (
              <div className="csrWarn" key={`${warning.code}-${index}`}>
                <div className="csrWarnCode">{warning.code}</div>
                <div className="csrWarnMsg">{warning.message}</div>
              </div>
            ))}
          </div>
        </Section>
      ) : null}
    </div>
  );
}
