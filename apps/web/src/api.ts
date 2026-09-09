const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

export function headers(): HeadersInit {
  const token = localStorage.getItem("opencra_token");
  const devUser = localStorage.getItem("opencra_dev_user") || "user-1";
  const devOrg = localStorage.getItem("opencra_dev_org") || "org-1";
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (token) h.Authorization = `Bearer ${token}`;
  else {
    h["X-Dev-User-Id"] = devUser;
    h["X-Dev-Org-Id"] = devOrg;
  }
  return h;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API}${path}`, { ...init, headers: { ...headers(), ...init?.headers } });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) return res.json() as Promise<T>;
  return (await res.blob()) as T;
}

export type Product = {
  id: string;
  name: string;
  version: string | null;
  market_member_states: string[];
};

export type CraCase = {
  id: string;
  product_id: string;
  status: string;
  case_type: string;
  awareness_at: string | null;
  early_warning_due_at: string | null;
  notification_due_at: string | null;
  final_report_due_at: string | null;
  overdue: string[];
  srp_reference_id: string | null;
  exploit_nature: string | null;
};

export type Match = {
  id: string;
  purl: string;
  cve_id: string | null;
  severity: string | null;
  in_kev: boolean;
  status: string;
  vex_status: string | null;
  summary: string | null;
  product_id: string | null;
};
