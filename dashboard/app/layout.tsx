import "./globals.css";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "SecAgent Platform",
  description: "Autonomous security agent platform — authorized, isolated-lab testing.",
};

const NAV = [
  ["/", "Overview"],
  ["/projects", "Projects"],
  ["/agents", "Agents"],
  ["/vulnerabilities", "Vulnerabilities"],
  ["/lab", "Security Lab"],
  ["/reports", "Reports"],
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="layout">
          <aside className="sidebar">
            <div className="brand">
              SecAgent
              <small>authorized · isolated-lab</small>
            </div>
            <nav className="nav">
              {NAV.map(([href, label]) => (
                <Link key={href} href={href}>{label}</Link>
              ))}
            </nav>
          </aside>
          <main className="main">{children}</main>
        </div>
      </body>
    </html>
  );
}
