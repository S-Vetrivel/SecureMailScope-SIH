import { Link, useLocation } from "react-router-dom";
import {
  LayoutDashboard,
  Upload,
  FileSearch,
  FileText,
  Shield,
} from "lucide-react";

const navItems = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/upload", label: "Upload PCAP", icon: Upload },
  { href: "/analyses", label: "Analyses", icon: FileSearch },
  { href: "/reports", label: "Reports", icon: FileText },
];

export default function Sidebar() {
  const location = useLocation();

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-icon">
          <Shield size={20} color="white" />
        </div>
        <div>
          <h1>SecureMailScope</h1>
          <span className="version">v1.0 — SIH 2026</span>
        </div>
      </div>
      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive =
            item.href === "/"
              ? location.pathname === "/"
              : location.pathname.startsWith(item.href);
          return (
            <Link
              key={item.href}
              to={item.href}
              className={`nav-link ${isActive ? "active" : ""}`}
            >
              <Icon className="nav-icon" size={20} />
              {item.label}
            </Link>
          );
        })}
      </nav>
      <div
        style={{
          padding: "16px 20px",
          borderTop: "1px solid var(--border)",
          fontSize: "11px",
          color: "var(--text-muted)",
        }}
      >
        NTRO PS 26159
        <br />
        AI-Assisted Crypto Posture
      </div>
    </aside>
  );
}
