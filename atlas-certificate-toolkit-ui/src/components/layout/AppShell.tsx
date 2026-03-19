import type { ReactNode } from "react";

type Props = {
  title?: string;
  subtitle?: string;
  children: ReactNode;
};

export function AppShell({ title = "Atlas Decodificador", subtitle, children }: Props) {
  return (
    <div className="app">
      <header className="topbar">
        <div>
          <div className="title">{title}</div>
          {subtitle ? <div className="subtitle">{subtitle}</div> : null}
        </div>
      </header>

      <main className="container">{children}</main>

      
    </div>
  );
}