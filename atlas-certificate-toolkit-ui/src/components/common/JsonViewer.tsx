import type { JsonValue } from "../../api/toolkit";

export function JsonViewer(props: { value: JsonValue | undefined }) {
  return (
    <pre className="input" style={{ whiteSpace: "pre-wrap", overflowX: "auto", margin: 0 }}>
      {JSON.stringify(props.value, null, 2)}
    </pre>
  );
}
