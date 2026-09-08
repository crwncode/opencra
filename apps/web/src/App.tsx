import { FormEvent, useEffect, useState } from "react";
import { Link, Navigate, Route, Routes, useNavigate, useParams } from "react-router-dom";
import { CraCase, Match, Product, api, headers } from "./api";

const AWARENESS_COPY =
  "I have completed an initial assessment and I am now aware that this is an actively exploited vulnerability or severe incident in our product. This starts the Article 14 24-hour and 72-hour clocks. A KEV match alone is not awareness.";

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <Link to="/" className="font-semibold tracking-tight">
          CRA-Shield
        </Link>
        <nav className="flex gap-4 text-sm text-slate-300">
          <Link to="/">Clock board</Link>
          <Link to="/products">Products</Link>
          <Link to="/vulns">Vulnerabilities</Link>
          <Link to="/billing">Billing</Link>
        </nav>
      </header>
      <main className="mx-auto max-w-6xl px-6 py-8">{children}</main>
    </div>
  );
}

function Login() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [org, setOrg] = useState("org-1");

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    localStorage.setItem("crashield_dev_user", email || "user-1");
    localStorage.setItem("crashield_dev_org", org);
    navigate("/");
  }

  return (
    <div className="mx-auto max-w-md py-24">
      <h1 className="text-2xl font-semibold">Sign in to CRA-Shield</h1>
      <p className="mt-2 text-sm text-slate-400">
        Production uses Supabase Auth (email or GitHub). Locally, these fields mint a
        development principal.
      </p>
      <form onSubmit={onSubmit} className="mt-6 space-y-3">
        <input
          className="w-full rounded border border-slate-700 bg-slate-900 px-3 py-2"
          placeholder="you@company.eu"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <input
          className="w-full rounded border border-slate-700 bg-slate-900 px-3 py-2"
          placeholder="org id"
          value={org}
          onChange={(e) => setOrg(e.target.value)}
        />
        <button className="w-full rounded bg-amber-400 px-3 py-2 font-medium text-slate-950">
          Continue
        </button>
      </form>
    </div>
  );
}

function ClockBoard() {
  const [cases, setCases] = useState<CraCase[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<CraCase[]>("/cases")
      .then(setCases)
      .catch((e: Error) => setError(e.message));
  }, []);

  return (
    <Shell>
      <h1 className="text-2xl font-semibold">CRA clock board</h1>
      <p className="mt-2 max-w-3xl text-sm text-slate-400">
        Candidates do not start a legal clock. Acknowledge awareness only after an initial
        assessment. 24h early warning and 72h notification run from awareness. The 14-day
        final report runs from when a fix is available.
      </p>
      {error && <p className="mt-4 text-red-400">{error}</p>}
      <div className="mt-6 overflow-x-auto rounded border border-slate-800">
        <table className="w-full text-left text-sm">
          <thead className="bg-slate-900 text-slate-400">
            <tr>
              <th className="px-3 py-2">Case</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Awareness</th>
              <th className="px-3 py-2">24h due</th>
              <th className="px-3 py-2">72h due</th>
              <th className="px-3 py-2">Final due</th>
            </tr>
          </thead>
          <tbody>
            {cases.map((c) => (
              <tr key={c.id} className="border-t border-slate-800">
                <td className="px-3 py-2 font-mono">
                  <Link className="text-amber-300" to={`/cases/${c.id}`}>
                    {c.id.slice(0, 8)}
                  </Link>
                </td>
                <td className="px-3 py-2">
                  {c.overdue?.length ? (
                    <span className="text-red-400">{c.status}</span>
                  ) : (
                    c.status
                  )}
                </td>
                <td className="px-3 py-2">{c.awareness_at ?? "—"}</td>
                <td className="px-3 py-2">{c.early_warning_due_at ?? "—"}</td>
                <td className="px-3 py-2">{c.notification_due_at ?? "—"}</td>
                <td className="px-3 py-2">{c.final_report_due_at ?? "—"}</td>
              </tr>
            ))}
            {!cases.length && (
              <tr>
                <td className="px-3 py-6 text-slate-500" colSpan={6}>
                  No cases yet. Sync a CLI scan with KEV hits (`opencra scan . --sync-cloud`).
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Shell>
  );
}

function CaseDetail() {
  const { id } = useParams();
  const [item, setItem] = useState<CraCase | null>(null);
  const [checked, setChecked] = useState(false);
  const [packet, setPacket] = useState<string>("");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [refId, setRefId] = useState("");

  async function refresh() {
    const rows = await api<CraCase[]>("/cases");
    setItem(rows.find((c) => c.id === id) ?? null);
  }

  useEffect(() => {
    refresh().catch(() => undefined);
  }, [id]);

  async function acknowledge() {
    if (!id || !checked) return;
    await api(`/cases/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ acknowledge: true }),
    });
    await refresh();
  }

  async function loadPacket(stage: string) {
    if (!id) return;
    const data = await api<{ markdown: string; fields: Record<string, string> }>(
      `/cases/${id}/srp/${stage}`,
    );
    setPacket(data.markdown);
    setFields(data.fields);
  }

  async function markSubmitted(stage: string) {
    if (!id) return;
    await api(`/cases/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ stage_submitted: stage, srp_reference_id: refId }),
    });
    await refresh();
  }

  if (!item) return <Shell>Loading…</Shell>;

  return (
    <Shell>
      <h1 className="text-2xl font-semibold">Case {item.id.slice(0, 8)}</h1>
      <p className="mt-1 text-sm text-slate-400">Status: {item.status}</p>

      {item.status === "candidate" && (
        <section className="mt-6 rounded border border-amber-700/50 bg-amber-950/30 p-4">
          <h2 className="font-medium">Acknowledge awareness</h2>
          <label className="mt-3 flex gap-2 text-sm">
            <input type="checkbox" checked={checked} onChange={(e) => setChecked(e.target.checked)} />
            <span>{AWARENESS_COPY}</span>
          </label>
          <button
            disabled={!checked}
            onClick={acknowledge}
            className="mt-4 rounded bg-amber-400 px-3 py-2 text-sm font-medium text-slate-950 disabled:opacity-40"
          >
            I am now aware — start the 24-hour clock
          </button>
        </section>
      )}

      <section className="mt-8">
        <h2 className="font-medium">SRP submission pack</h2>
        <p className="text-sm text-slate-400">
          ENISA has no API. Copy fields into the portal, then mark the stage submitted.
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          {["early_warning", "notification", "final"].map((stage) => (
            <button
              key={stage}
              className="rounded border border-slate-700 px-3 py-1 text-sm"
              onClick={() => loadPacket(stage)}
            >
              Draft {stage.replace("_", " ")}
            </button>
          ))}
        </div>
        {!!Object.keys(fields).length && (
          <div className="mt-4 space-y-2">
            {Object.entries(fields).map(([k, v]) => (
              <div key={k} className="flex items-center gap-2 text-sm">
                <span className="w-56 text-slate-400">{k}</span>
                <code className="flex-1 truncate rounded bg-slate-900 px-2 py-1">{v}</code>
                <button
                  className="text-amber-300"
                  onClick={() => navigator.clipboard.writeText(String(v))}
                >
                  Copy
                </button>
              </div>
            ))}
          </div>
        )}
        {packet && <pre className="mt-4 overflow-x-auto rounded bg-slate-900 p-4 text-xs">{packet}</pre>}
        <div className="mt-4 flex gap-2">
          <input
            className="flex-1 rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
            placeholder="SRP reference ID (after you file)"
            value={refId}
            onChange={(e) => setRefId(e.target.value)}
          />
          <button className="rounded border border-slate-600 px-3 py-2 text-sm" onClick={() => markSubmitted("early_warning")}>
            Mark early warning submitted
          </button>
          <button className="rounded border border-slate-600 px-3 py-2 text-sm" onClick={() => markSubmitted("notification")}>
            Mark notification submitted
          </button>
          <button className="rounded border border-slate-600 px-3 py-2 text-sm" onClick={() => markSubmitted("final")}>
            Mark final submitted
          </button>
        </div>
      </section>
    </Shell>
  );
}

function Products() {
  const [rows, setRows] = useState<Product[]>([]);
  const [name, setName] = useState("");

  async function load() {
    setRows(await api<Product[]>("/products"));
  }
  useEffect(() => {
    load().catch(() => undefined);
  }, []);

  async function create(e: FormEvent) {
    e.preventDefault();
    await api("/products", { method: "POST", body: JSON.stringify({ name }) });
    setName("");
    await load();
  }

  async function downloadAudit(id: string) {
    const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
    const res = await fetch(`${API}/products/${id}/audit-report`, { headers: headers() });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "cra-audit-report.pdf";
    a.click();
  }

  return (
    <Shell>
      <h1 className="text-2xl font-semibold">Products</h1>
      <form onSubmit={create} className="mt-4 flex gap-2">
        <input
          className="rounded border border-slate-700 bg-slate-900 px-3 py-2"
          placeholder="Product with digital elements"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <button className="rounded bg-slate-100 px-3 py-2 text-slate-950">Add</button>
      </form>
      <ul className="mt-6 space-y-2">
        {rows.map((p) => (
          <li key={p.id} className="flex items-center justify-between rounded border border-slate-800 px-3 py-2">
            <span>
              {p.name} <span className="text-slate-500">{p.version}</span>
            </span>
            <button className="text-sm text-amber-300" onClick={() => downloadAudit(p.id)}>
              Audit report
            </button>
          </li>
        ))}
      </ul>
    </Shell>
  );
}

function Vulns() {
  const [rows, setRows] = useState<Match[]>([]);
  useEffect(() => {
    api<Match[]>("/matches")
      .then(setRows)
      .catch(() => undefined);
  }, []);
  return (
    <Shell>
      <h1 className="text-2xl font-semibold">Dependency vulnerabilities</h1>
      <table className="mt-4 w-full text-left text-sm">
        <thead className="text-slate-400">
          <tr>
            <th className="py-2">PURL</th>
            <th>CVE</th>
            <th>Severity</th>
            <th>KEV</th>
            <th>VEX</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((m) => (
            <tr key={m.id} className="border-t border-slate-800">
              <td className="py-2 font-mono text-xs">{m.purl}</td>
              <td>{m.cve_id}</td>
              <td>{m.severity}</td>
              <td>{m.in_kev ? "KEV" : ""}</td>
              <td>{m.vex_status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </Shell>
  );
}

function Billing() {
  async function upgrade(tier: string) {
    const data = await api<{ url?: string; tier?: string }>("/billing/checkout", {
      method: "POST",
      body: JSON.stringify({ tier }),
    });
    if (data.url) window.location.href = data.url;
    else alert(`Dev upgrade: ${data.tier}`);
  }
  return (
    <Shell>
      <h1 className="text-2xl font-semibold">Billing</h1>
      <p className="mt-2 text-sm text-slate-400">
        Community is free. Pro $79/mo (launch $49). Pro Plus $149. Enterprise from $499.
      </p>
      <div className="mt-6 flex gap-3">
        <button className="rounded bg-amber-400 px-4 py-2 text-slate-950" onClick={() => upgrade("pro")}>
          Upgrade to Pro
        </button>
        <button className="rounded border border-slate-600 px-4 py-2" onClick={() => upgrade("pro_plus")}>
          Upgrade to Pro Plus
        </button>
      </div>
    </Shell>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/" element={<ClockBoard />} />
      <Route path="/cases/:id" element={<CaseDetail />} />
      <Route path="/products" element={<Products />} />
      <Route path="/vulns" element={<Vulns />} />
      <Route path="/billing" element={<Billing />} />
      <Route path="*" element={<Navigate to="/" />} />
    </Routes>
  );
}
