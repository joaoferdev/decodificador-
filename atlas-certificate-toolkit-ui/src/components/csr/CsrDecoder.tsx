import { useMemo, useState } from "react";
import {
  decodeCsrFromFile,
  decodeCsrFromPem,
  type DecodedCsr,
  type JsonValue,
  type Warning
} from "../../api/toolkit";
import { FileDrop } from "../common/FileDrop";
import { JsonViewer } from "../common/JsonViewer";
import { CsrResult } from "./CsrResult";
import { Alert } from "../common/Alert";

export function CsrDecoder() {
  const [pem, setPem] = useState("");
  const [decoded, setDecoded] = useState<DecodedCsr | null>(null);
  const [warnings, setWarnings] = useState<Warning[]>([]);
  const [raw, setRaw] = useState<JsonValue | undefined>(undefined);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const canDecode = useMemo(() => pem.trim().length > 0, [pem]);

  async function onDecodeText() {
    setErr(null);
    setLoading(true);
    try {
      const res = await decodeCsrFromPem(pem);
      setDecoded(res.decoded);
      setWarnings(res.warnings ?? []);
      setRaw(res as JsonValue);
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : "Erro ao decodificar");
    } finally {
      setLoading(false);
    }
  }

  async function onDecodeFile(file: File) {
    setErr(null);
    setLoading(true);
    try {
      const res = await decodeCsrFromFile(file);
      setDecoded(res.decoded);
      setWarnings(res.warnings ?? []);
      setRaw(res as JsonValue);
      setPem("");
    } catch (e: unknown) {
      setErr(e instanceof Error ? e.message : "Erro ao decodificar");
    } finally {
      setLoading(false);
    }
  }

  function onClear() {
    setPem("");
    setDecoded(null);
    setWarnings([]);
    setRaw(undefined);
    setErr(null);
  }

  return (
    <div className="csrPage">
      <div className="panel csrCard">
        <div className="csrHeader">
          <div>
            <div className="csrTitle">CSR Decoder</div>
            <div className="csrHint">Cole um CSR PEM (BEGIN/END) ou envie um arquivo.</div>
          </div>

          <div className="csrHeaderRight">
            {decoded ? <span className="csrPill ok">Decodificado</span> : <span className="csrPill">Aguardando</span>}

            <button className="btn" disabled={loading} onClick={onClear} type="button">
              Limpar / Novo CSR
            </button>
          </div>
        </div>

        <div className="csrEditor">
          <div className="csrLabelRow">
            <div>
              <div className="csrLabel">Colar CSR (PEM)</div>
              <div className="csrLabelHint">Dica: inclua BEGIN/END</div>
            </div>

            <span className="csrPill">Cole o PEM</span>
          </div>

          <textarea
            className="csrTextarea"
            value={pem}
            onChange={(e) => setPem(e.target.value)}
            placeholder={"-----BEGIN CERTIFICATE REQUEST-----\n..."}
            spellCheck={false}
          />

          <div className="csrActions">
            <button
              className="btn primary"
              disabled={!canDecode || loading}
              onClick={onDecodeText}
              type="button"
            >
              {loading ? "Decodificando..." : "Decodificar"}
            </button>

            <button className="btn" disabled={loading} onClick={onClear} type="button">
              Limpar
            </button>
          </div>

          {err ? (
            <div style={{ marginTop: 12 }}>
              <Alert kind="err" title="Erro" message={err} />
            </div>
          ) : null}
        </div>

        <div className="divider" />

        <div className="csrSubHeader">
          <div>
            <div className="csrLabel">Ou faca upload do csr.pem</div>
            <div className="csrHint">Arraste e solte ou selecione o arquivo.</div>
          </div>
        </div>

        <div className="csrDrop">
          <FileDrop
            label="Solte aqui / Selecionar"
            accept=".pem,.csr,.txt"
            multiple={false}
            onFiles={(fs) => onDecodeFile(fs[0])}
          />
        </div>
      </div>

      <div className="panel csrResult">
        <div className="csrTitle">Resultado</div>
        <div className="csrHint">Detalhes do CSR decodificado.</div>

        <div className="csrResultBody">
          {!decoded ? (
            <div className="csrEmptyState">
              <div className="csrEmptyTitle">Nenhum CSR decodificado ainda.</div>
              <div className="csrEmptyHint">Cole ou envie um arquivo ao lado.</div>
            </div>
          ) : (
            <>
              <CsrResult decoded={decoded} warnings={warnings} />

              <div className="divider" />

              <details className="csrAccordion">
                <summary>Raw JSON (debug/integracao)</summary>
                <div style={{ marginTop: 10 }}>
                  <JsonViewer value={raw} />
                </div>
              </details>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
