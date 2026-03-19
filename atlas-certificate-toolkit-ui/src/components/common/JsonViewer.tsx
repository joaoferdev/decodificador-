export function JsonViewer(props: { value: any }) {
  return (
    <pre className="input" style={{ whiteSpace: "pre-wrap", overflowX: "auto", margin: 0 }}>
      {JSON.stringify(props.value, null, 2)}
    </pre>
  );
}