export function Alert(props: { kind: "ok" | "warn" | "err"; title: string; message?: string }) {
  const cls =
    props.kind === "ok" ? "badge badgeOk" : props.kind === "warn" ? "badge badgeWarn" : "badge badgeErr";
  return (
    <div className={cls} style={{ width: "100%" }}>
      <strong>{props.title}</strong>
      {props.message ? <span className="small">{props.message}</span> : null}
    </div>
  );
}