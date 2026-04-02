import type { ReactNode } from "react";

type Props = {
  children: ReactNode;
};

export function AppShell({ children }: Props) {
  return (
    <div className="appShell">
      <header className="topbar">
        <div className="topbarInner">
          <div className="brandBlock">
            <div className="brandMark">X.DIGITAL BRASIL</div>
            <div className="brandMeta">ICP-Brasil | SSL/TLS | Certificados corporativos</div>
          </div>
        </div>
      </header>

      <main className="container">{children}</main>
    </div>
  );
}
