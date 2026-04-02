export function Alert(props: { kind: "ok" | "info" | "warn" | "err"; title: string; message?: string }) {
  const cls =
    props.kind === "ok"
      ? "alert alert--ok"
      : props.kind === "info"
        ? "alert alert--info"
        : props.kind === "warn"
          ? "alert alert--warn"
          : "alert alert--err";
  return (
    <div className={cls} style={{ width: "100%" }} role={props.kind === "err" ? "alert" : "status"}>
      <strong>{props.title}</strong>
      {props.message ? <span>{props.message}</span> : null}
    </div>
  );
}
