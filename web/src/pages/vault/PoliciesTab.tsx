import { useState, useEffect, useCallback, useMemo } from "react";
import YAML from "yaml";
import {
  useVaultParams,
  LoadingSpinner,
  ErrorBanner,
  EmptyState,
  StatusBadge,
  timeAgo,
} from "./shared";
import DataTable, { type Column } from "../../components/DataTable";
import Sheet from "../../components/Sheet";
import Modal from "../../components/Modal";
import Button from "../../components/Button";
import Select from "../../components/Select";
import FormField from "../../components/FormField";
import Toggle from "../../components/Toggle";
import type { Auth } from "../../components/ProposalPreview";
import { apiFetch } from "../../lib/api";

const POLICY_API_VERSION = "policy.agentvault/v1";
const POLICY_KIND = "Policy";

/** Mirrors internal/policy slug validation. */
const POLICY_SLUG_RE = /^[a-z0-9](?:[a-z0-9-]{1,62}[a-z0-9])?$/;

const HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "*"] as const;

interface VaultServiceRow {
  host: string;
  description?: string;
  auth?: Auth;
  substitutions?: { key: string }[];
}

function authCredentialKeys(auth: Auth | undefined): string[] {
  if (!auth?.type) return [];
  switch (auth.type) {
    case "bearer":
      return auth.token ? [auth.token] : [];
    case "basic": {
      const out: string[] = [];
      if (auth.username) out.push(auth.username);
      if (auth.password) out.push(auth.password);
      return out;
    }
    case "api-key":
      return auth.key ? [auth.key] : [];
    case "custom": {
      const re = /\{\{\s*(\w+)\s*\}\}/g;
      const seen = new Set<string>();
      for (const v of Object.values(auth.headers ?? {})) {
        let m: RegExpExecArray | null;
        re.lastIndex = 0;
        while ((m = re.exec(v)) !== null) seen.add(m[1]);
      }
      return [...seen];
    }
    default:
      return [];
  }
}

function serviceAllCredentialKeys(s: VaultServiceRow): string[] {
  const seen = new Set<string>();
  for (const k of authCredentialKeys(s.auth)) {
    if (k) seen.add(k);
  }
  for (const sub of s.substitutions ?? []) {
    if (sub.key) seen.add(sub.key);
  }
  return [...seen];
}

/** Credential key written into policy YAML: derived from service auth (not shown in UI). */
function inferCredentialKeyForService(svc: VaultServiceRow | undefined): string {
  if (!svc) return "*";
  const keys = serviceAllCredentialKeys(svc);
  if (keys.length === 0) return "*";
  if (keys.length === 1) return keys[0]!;
  return "*";
}

const METHOD_PILLS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] as const;

interface PolicyFormRule {
  id: string;
  effect: "allow" | "deny";
  methods: string[];
  pathPatterns: string;
}

interface PolicyFormState {
  policyId: string;
  description: string;
  serviceHost: string;
  credentialKey: string;
  rules: PolicyFormRule[];
}

function defaultPolicyForm(): PolicyFormState {
  return {
    policyId: "",
    description: "",
    serviceHost: "",
    credentialKey: "*",
    rules: [
      {
        id: "allow-read",
        effect: "allow",
        methods: ["GET"],
        pathPatterns: "/**",
      },
    ],
  };
}

function yamlScalar(s: string): string {
  if (s === "") return '""';
  if (/^[\w.*@/-]+$/.test(s)) return s;
  return JSON.stringify(s);
}

function buildPolicyYAML(vault: string, form: PolicyFormState): string {
  const lines: string[] = [];
  lines.push(`apiVersion: ${POLICY_API_VERSION}`);
  lines.push(`kind: ${POLICY_KIND}`);
  lines.push("metadata:");
  lines.push(`  id: ${form.policyId}`);
  lines.push(`  vault: ${vault}`);
  lines.push(`  description: ${yamlScalar(form.description)}`);
  lines.push("spec:");
  lines.push("  resources:");
  lines.push(`    - credential_key: ${yamlScalar(form.credentialKey)}`);
  lines.push(`      service_host: ${yamlScalar(form.serviceHost)}`);
  lines.push("  rules:");
  for (const r of form.rules) {
    lines.push(`    - id: ${r.id}`);
    lines.push(`      effect: ${r.effect}`);
    if (r.methods.length > 0) {
      lines.push(`      methods: [${r.methods.map((m) => m.toUpperCase()).join(", ")}]`);
    }
    const pats = r.pathPatterns
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    if (pats.length > 0) {
      lines.push(`      path_patterns: [${pats.map((p) => yamlScalar(p)).join(", ")}]`);
    }
  }
  return `${lines.join("\n")}\n`;
}

function policyFormFromYaml(
  src: string,
): { ok: true; form: PolicyFormState } | { ok: false; error: string } {
  let doc: Record<string, unknown>;
  try {
    doc = YAML.parse(src) as Record<string, unknown>;
  } catch {
    return { ok: false, error: "Invalid YAML." };
  }
  if (doc.apiVersion !== POLICY_API_VERSION || doc.kind !== POLICY_KIND) {
    return { ok: false, error: "Not a policy.agentvault/v1 Policy document." };
  }
  const spec = doc.spec as Record<string, unknown> | undefined;
  const resources = spec?.resources as unknown[] | undefined;
  if (!Array.isArray(resources) || resources.length === 0) {
    return { ok: false, error: "Policy has no resources." };
  }
  if (resources.length > 1) {
    return {
      ok: false,
      error:
        "This policy has multiple resources. The visual editor supports one service resource; use the CLI for advanced policies.",
    };
  }
  const constraints = spec?.constraints as Record<string, unknown> | undefined;
  if (constraints && typeof constraints === "object" && Object.keys(constraints).length > 0) {
    return {
      ok: false,
      error:
        "This policy sets constraints (body, rate limits, time windows, …). Edit it with the CLI.",
    };
  }
  const res0 = resources[0] as Record<string, unknown>;
  const credentialKey = String(res0.credential_key ?? "");
  const serviceHost = String(res0.service_host ?? "");
  if (!credentialKey || !serviceHost) {
    return { ok: false, error: "Resource is missing credential_key or service_host." };
  }
  const meta = doc.metadata as Record<string, unknown> | undefined;
  const policyId = String(meta?.id ?? "");
  const description =
    meta?.description === null || meta?.description === undefined
      ? ""
      : String(meta.description);
  const rulesIn = (spec?.rules as unknown[]) ?? [];
  if (!Array.isArray(rulesIn) || rulesIn.length === 0) {
    return { ok: false, error: "Policy has no rules." };
  }
  const rules: PolicyFormRule[] = rulesIn.map((raw, i) => {
    const r = raw as Record<string, unknown>;
    const methodsRaw = r.methods;
    let methods: string[] = [];
    if (Array.isArray(methodsRaw)) {
      methods = methodsRaw.map((m) => String(m).toUpperCase());
      if (methods.length === 1 && methods[0] === "*") {
        methods = [];
      }
    }
    const pp = r.path_patterns;
    let pathPatterns = "";
    if (Array.isArray(pp) && pp.length > 0) {
      pathPatterns = pp.map((p) => String(p)).join(", ");
    } else {
      pathPatterns = "/**";
    }
    return {
      id: String(r.id ?? `rule-${i + 1}`),
      effect: r.effect === "deny" ? "deny" : "allow",
      methods,
      pathPatterns,
    };
  });
  return {
    ok: true,
    form: { policyId, description, serviceHost, credentialKey, rules },
  };
}

interface PolicyViewResource {
  credential_key: string;
  service_host: string;
}

interface PolicyViewRule {
  id: string;
  effect: string;
  methods: string[];
  path_patterns: string[];
}

interface PolicyViewModel {
  description: string;
  resources: PolicyViewResource[];
  rules: PolicyViewRule[];
}

function parsePolicyYamlForView(src: string): PolicyViewModel | null {
  try {
    const doc = YAML.parse(src) as Record<string, unknown>;
    if (doc.apiVersion !== POLICY_API_VERSION || doc.kind !== POLICY_KIND) return null;
    const spec = doc.spec as Record<string, unknown> | undefined;
    const meta = doc.metadata as Record<string, unknown> | undefined;
    const resourcesRaw = spec?.resources as unknown[] | undefined;
    const resources: PolicyViewResource[] = [];
    if (Array.isArray(resourcesRaw)) {
      for (const r of resourcesRaw) {
        const o = r as Record<string, unknown>;
        resources.push({
          credential_key: String(o.credential_key ?? ""),
          service_host: String(o.service_host ?? ""),
        });
      }
    }
    const rulesIn = (spec?.rules as unknown[]) ?? [];
    const rules: PolicyViewRule[] = [];
    if (Array.isArray(rulesIn)) {
      for (const raw of rulesIn) {
        const r = raw as Record<string, unknown>;
        const methodsRaw = r.methods;
        const methods = Array.isArray(methodsRaw)
          ? methodsRaw.map((m) => String(m))
          : [];
        const pp = r.path_patterns;
        const path_patterns = Array.isArray(pp) ? pp.map((p) => String(p)) : [];
        rules.push({
          id: String(r.id ?? ""),
          effect: String(r.effect ?? ""),
          methods,
          path_patterns,
        });
      }
    }
    const description =
      meta?.description === null || meta?.description === undefined
        ? ""
        : String(meta.description);
    return { description, resources, rules };
  } catch {
    return null;
  }
}

function validatePolicyForm(
  form: PolicyFormState,
  mode: "create" | "version",
  lockedPolicyId: string | undefined,
): string | null {
  if (!POLICY_SLUG_RE.test(form.policyId)) {
    return "Policy ID must be a lowercase slug (3–64 characters, hyphens allowed).";
  }
  if (mode === "version" && lockedPolicyId && form.policyId !== lockedPolicyId) {
    return "Policy ID must stay the same when publishing a new version.";
  }
  if (!form.serviceHost.trim()) {
    return "Select a service (host).";
  }
  if (!form.credentialKey.trim()) {
    return "Credential key is required.";
  }
  if (form.rules.length === 0) {
    return "Add at least one rule.";
  }
  for (let i = 0; i < form.rules.length; i++) {
    const r = form.rules[i];
    if (!POLICY_SLUG_RE.test(r.id)) {
      return `Rule ${i + 1}: ID must be a valid slug.`;
    }
    const pats = r.pathPatterns
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);
    if (pats.length === 0) {
      return `Rule ${i + 1}: add at least one path pattern (e.g. /**), comma-separated.`;
    }
    for (const p of pats) {
      if (!p.startsWith("/")) {
        return `Rule ${i + 1}: path pattern ${JSON.stringify(p)} must start with /.`;
      }
    }
    for (const m of r.methods) {
      const up = m.toUpperCase();
      if (!HTTP_METHODS.includes(up as (typeof HTTP_METHODS)[number])) {
        return `Rule ${i + 1}: unknown HTTP method ${m}.`;
      }
    }
  }
  return null;
}

async function readApiError(resp: Response): Promise<string> {
  const data = await resp.json().catch(() => ({}));
  return (data as { error?: string }).error || resp.statusText || "Request failed";
}

type Panel = "policies" | "grants";

/** Built-in installable policy from GET /v1/policy-catalog (local registry). */
interface PolicyCatalogEntry {
  id: string;
  name: string;
  description: string;
  service_catalog_id: string;
  default_policy_id: string;
  service_host: string;
  suggested_credential_key: string;
  yaml_template: string;
}

function renderCatalogInstallYaml(
  entry: PolicyCatalogEntry,
  vault: string,
  policyId: string,
): string {
  const pid = policyId.trim() || entry.default_policy_id;
  return entry.yaml_template
    .split("{{VAULT}}")
    .join(vault)
    .split("{{POLICY_ID}}")
    .join(pid)
    .split("{{SERVICE_HOST}}")
    .join(entry.service_host)
    .split("{{CREDENTIAL_KEY}}")
    .join(entry.suggested_credential_key);
}

interface PolicySummary {
  id: string;
  version: number;
  enabled: boolean;
  description?: string;
  yaml_source: string;
  content_hash: string;
  parent_hash?: string;
  authored_by: string;
  authored_at: string;
}

function policyFromAPIPayload(data: Record<string, unknown>): PolicySummary {
  const ph = data.parent_hash;
  return {
    id: String(data.id ?? ""),
    version: Number(data.version ?? 0),
    enabled: Boolean(data.enabled),
    description: data.description != null ? String(data.description) : undefined,
    yaml_source: String(data.yaml_source ?? ""),
    content_hash: String(data.content_hash ?? ""),
    parent_hash:
      ph != null && String(ph) !== "" ? String(ph) : undefined,
    authored_by: String(data.authored_by ?? ""),
    authored_at: String(data.authored_at ?? ""),
  };
}

function downloadPolicyYaml(p: PolicySummary) {
  const blob = new Blob([p.yaml_source], { type: "text/yaml;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  try {
    const a = document.createElement("a");
    a.href = url;
    a.download = `${p.id}-v${p.version}.yaml`;
    a.rel = "noopener";
    document.body.appendChild(a);
    a.click();
    a.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

interface GrantRow {
  id: string;
  subject_type: string;
  subject_id: string;
  policy_id: string;
  policy_version: number;
  conditions?: Record<string, unknown>;
  granted_by: string;
  granted_at: string;
  expires_at?: string;
  revoked_at?: string;
  revoked_by?: string;
}

type OpenPolicyEditor = {
  mode: "create" | "version";
  lockedPolicyId?: string;
  form: PolicyFormState;
  parseError?: string;
};

function PolicyEditorBody({
  editor,
  vaultServices,
  policySaveError,
  onPolicyServiceChange,
  updatePolicyForm,
  addPolicyRule,
  removePolicyRule,
  updateRule,
  toggleRuleMethod,
}: {
  editor: OpenPolicyEditor;
  vaultServices: VaultServiceRow[];
  policySaveError: string;
  onPolicyServiceChange: (host: string) => void;
  updatePolicyForm: (u: (f: PolicyFormState) => PolicyFormState) => void;
  addPolicyRule: () => void;
  removePolicyRule: (index: number) => void;
  updateRule: (index: number, patch: Partial<PolicyFormRule>) => void;
  toggleRuleMethod: (ruleIndex: number, method: string) => void;
}) {
  const { form, mode, lockedPolicyId, parseError } = editor;
  const catalogHosts = new Set(vaultServices.map((s) => s.host));
  const orphanHost = Boolean(form.serviceHost && !catalogHosts.has(form.serviceHost));
  const [openRuleIdx, setOpenRuleIdx] = useState(0);

  return (
    <div className="space-y-5">
      {parseError ? (
        <ErrorBanner
          message={`${parseError} The YAML is still shown on the policy detail view; use the CLI to edit this version.`}
        />
      ) : null}
      {!parseError && policySaveError ? (
        <p className="text-sm text-danger">{policySaveError}</p>
      ) : null}
      {!parseError && (
        <>
          <FormField label="Policy Slug">
            <input
              type="text"
              className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm font-mono text-text disabled:opacity-60"
              value={form.policyId}
              disabled={mode === "version"}
              placeholder="e.g. stripe-readonly"
              autoComplete="off"
              onChange={(e) => updatePolicyForm((f) => ({ ...f, policyId: e.target.value.trim() }))}
            />
            {mode === "version" && lockedPolicyId ? (
              <p className="text-xs text-text-dim mt-1">ID is fixed for new versions ({lockedPolicyId}).</p>
            ) : null}
          </FormField>

          <FormField label="Description (optional)">
            <input
              type="text"
              className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text"
              value={form.description}
              placeholder="What this policy is for?"
              onChange={(e) => updatePolicyForm((f) => ({ ...f, description: e.target.value }))}
            />
          </FormField>

          <FormField
            label="Service"
            helperText={
              "Scopes this policy to this service’s host."
            }
          >
            {vaultServices.length === 0 ? (
              <p className="text-sm text-text-muted py-2">Loading services…</p>
            ) : (
              <Select
                value={form.serviceHost}
                onChange={(e) => onPolicyServiceChange(e.target.value)}
              >
                <option value="">Select a service…</option>
                {orphanHost ? (
                  <option value={form.serviceHost}>
                    {form.serviceHost} (from policy — not in catalog)
                  </option>
                ) : null}
                {vaultServices.map((s) => (
                  <option key={s.host} value={s.host}>
                    {s.host}
                    {s.description ? ` — ${s.description}` : ""}
                  </option>
                ))}
              </Select>
            )}
          </FormField>

          <div className="space-y-3">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-xs font-semibold text-text-dim uppercase tracking-wider">
                Rules
              </h3>
              <Button
                type="button"
                variant="secondary"
                className="py-1.5! px-3! text-xs!"
                onClick={() => {
                  addPolicyRule();
                  setOpenRuleIdx(form.rules.length);
                }}
              >
                Add rule
              </Button>
            </div>
            {form.rules.map((rule, idx) => {
              const expanded = openRuleIdx === idx;
              const methodPillClass = (active: boolean) =>
                `px-2.5 py-1.5 rounded-md text-xs font-semibold transition-colors border ${
                  active
                    ? "bg-surface text-text border-border shadow-sm"
                    : "bg-transparent text-text-muted border-transparent hover:text-text hover:bg-bg/80"
                }`;
              const allMethods = rule.methods.length === 0;
              return (
                <div
                  key={`${rule.id}-${idx}`}
                  className="rounded-lg border border-border bg-bg/20 overflow-hidden"
                >
                  <button
                    type="button"
                    className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-bg/50 transition-colors"
                    onClick={() => setOpenRuleIdx(expanded ? -1 : idx)}
                  >
                    <span className="text-text-dim text-xs w-6">{expanded ? "▼" : "▶"}</span>
                    <span className="font-mono text-sm text-text flex-1 min-w-0 truncate">
                      {rule.id || `rule-${idx + 1}`}
                    </span>
                    <span
                      className={`shrink-0 text-xs font-semibold px-2 py-0.5 rounded-md border ${
                        rule.effect === "allow"
                          ? "bg-success-bg text-success border-success/20"
                          : "bg-danger-bg text-danger border-danger/20"
                      }`}
                    >
                      {rule.effect}
                    </span>
                  </button>
                  {expanded ? (
                    <div className="px-4 pb-4 pt-1 border-t border-border space-y-4 bg-bg/30">
                      <div className="flex justify-end">
                        {form.rules.length > 1 ? (
                          <button
                            type="button"
                            className="text-xs text-danger hover:underline"
                            onClick={() => {
                              removePolicyRule(idx);
                              setOpenRuleIdx((prev) => {
                                if (prev === idx) return Math.max(0, idx - 1);
                                if (prev > idx) return prev - 1;
                                return prev;
                              });
                            }}
                          >
                            Remove rule
                          </button>
                        ) : null}
                      </div>
                      <div className="grid gap-3 sm:grid-cols-2">
                        <FormField label="Rule ID">
                          <input
                            type="text"
                            className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm font-mono text-text"
                            value={rule.id}
                            onChange={(e) => updateRule(idx, { id: e.target.value.trim() })}
                          />
                        </FormField>
                        <FormField label="Effect">
                          <Select
                            value={rule.effect}
                            onChange={(e) =>
                              updateRule(idx, { effect: e.target.value as "allow" | "deny" })
                            }
                          >
                            <option value="allow">allow</option>
                            <option value="deny">deny</option>
                          </Select>
                        </FormField>
                      </div>
                      <FormField
                        label="HTTP methods"
                        helperText="All = any method. Otherwise toggle verbs; order in the list does not matter."
                      >
                        <div className="flex flex-wrap gap-1.5 p-1.5 rounded-lg bg-bg/80 border border-border">
                          <button
                            type="button"
                            className={methodPillClass(allMethods)}
                            onClick={() => updateRule(idx, { methods: [] })}
                          >
                            All
                          </button>
                          {METHOD_PILLS.map((m) => {
                            const on = rule.methods.some((x) => x.toUpperCase() === m);
                            return (
                              <button
                                key={m}
                                type="button"
                                className={methodPillClass(on)}
                                onClick={() => {
                                  if (allMethods) {
                                    updateRule(idx, { methods: [m] });
                                  } else {
                                    toggleRuleMethod(idx, m);
                                  }
                                }}
                              >
                                {m}
                              </button>
                            );
                          })}
                        </div>
                        <div className="flex flex-wrap gap-2 mt-2">
                          <button
                            type="button"
                            className="text-xs text-primary hover:underline"
                            onClick={() => updateRule(idx, { methods: ["GET", "HEAD"] })}
                          >
                            Read-only
                          </button>
                          <span className="text-text-dim">·</span>
                          <button
                            type="button"
                            className="text-xs text-primary hover:underline"
                            onClick={() =>
                              updateRule(idx, {
                                methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
                              })
                            }
                          >
                            API (no HEAD)
                          </button>
                        </div>
                      </FormField>
                      <FormField
                        label="Path patterns"
                        helperText={
                          "Comma-separated path globs — * is one segment, ** is the rest of the path."
                        }
                      >
                        <input
                          type="text"
                          className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm font-mono text-text"
                          value={rule.pathPatterns}
                          onChange={(e) => updateRule(idx, { pathPatterns: e.target.value })}
                        />
                      </FormField>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

export default function PoliciesTab() {
  const { vaultName, vaultRole } = useVaultParams();
  const canAuthorPolicies = vaultRole === "admin" || vaultRole === "member";
  const [panel, setPanel] = useState<Panel>("policies");

  const [policies, setPolicies] = useState<PolicySummary[]>([]);
  const [grants, setGrants] = useState<GrantRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [engineOff, setEngineOff] = useState(false);

  const [policySheet, setPolicySheet] = useState<PolicySummary | null>(null);
  const [versions, setVersions] = useState<PolicySummary[]>([]);
  const [versionsLoading, setVersionsLoading] = useState(false);

  const [grantSheet, setGrantSheet] = useState<GrantRow | null>(null);

  const [policyEditor, setPolicyEditor] = useState<
    | null
    | {
        mode: "create" | "version";
        lockedPolicyId?: string;
        form: PolicyFormState;
        parseError?: string;
      }
  >(null);
  const [policySaveLoading, setPolicySaveLoading] = useState(false);
  const [policySaveError, setPolicySaveError] = useState("");

  const [policyDetailPatchLoading, setPolicyDetailPatchLoading] = useState(false);
  const [policyDetailError, setPolicyDetailError] = useState("");

  const [grantModalOpen, setGrantModalOpen] = useState(false);
  const [grantAgents, setGrantAgents] = useState<{ name: string }[]>([]);
  const [grantAgentName, setGrantAgentName] = useState("");
  const [grantPolicyId, setGrantPolicyId] = useState("");
  const [grantPolicyVersion, setGrantPolicyVersion] = useState("");
  const [grantExpiresLocal, setGrantExpiresLocal] = useState("");
  const [grantSubmitLoading, setGrantSubmitLoading] = useState(false);
  const [grantFormError, setGrantFormError] = useState("");

  const [vaultServices, setVaultServices] = useState<VaultServiceRow[]>([]);

  const [policyInstallOpen, setPolicyInstallOpen] = useState(false);
  const [policyCatalog, setPolicyCatalog] = useState<PolicyCatalogEntry[]>([]);
  const [policyCatalogLoading, setPolicyCatalogLoading] = useState(false);
  const [policyCatalogError, setPolicyCatalogError] = useState("");
  const [selectedCatalogTemplateId, setSelectedCatalogTemplateId] = useState<string | null>(null);
  const [installPolicyId, setInstallPolicyId] = useState("");
  const [installSubmitLoading, setInstallSubmitLoading] = useState(false);
  const [installFormError, setInstallFormError] = useState("");

  const [revokeGrantId, setRevokeGrantId] = useState<string | null>(null);
  const [revokeLoading, setRevokeLoading] = useState(false);

  const base = `/v1/vaults/${encodeURIComponent(vaultName)}`;

  const loadPolicies = useCallback(async () => {
    const resp = await apiFetch(`${base}/policies`);
    if (resp.status === 503) {
      setEngineOff(true);
      setPolicies([]);
      return;
    }
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.message || data.error || "Failed to load policies");
    }
    setEngineOff(false);
    const data = await resp.json();
    setPolicies(data.policies ?? []);
  }, [base]);

  const loadGrants = useCallback(async () => {
    const resp = await apiFetch(`${base}/grants`);
    if (resp.status === 503) {
      setEngineOff(true);
      setGrants([]);
      return;
    }
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.message || data.error || "Failed to load grants");
    }
    setEngineOff(false);
    const data = await resp.json();
    setGrants(data.grants ?? []);
  }, [base]);

  const refresh = useCallback(async () => {
    setError("");
    setLoading(true);
    try {
      await Promise.all([loadPolicies(), loadGrants()]);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    } finally {
      setLoading(false);
    }
  }, [loadPolicies, loadGrants]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    if (!policyInstallOpen) return;
    if (policyCatalog.length > 0) return;
    let cancelled = false;
    setPolicyCatalogLoading(true);
    setPolicyCatalogError("");
    apiFetch("/v1/policy-catalog")
      .then(async (resp) => {
        if (!resp.ok) {
          const data = await resp.json().catch(() => ({}));
          throw new Error((data as { error?: string }).error || "Failed to load policy catalog");
        }
        return resp.json() as Promise<{ policies?: PolicyCatalogEntry[] }>;
      })
      .then((data) => {
        if (!cancelled) setPolicyCatalog(data.policies ?? []);
      })
      .catch((e) => {
        if (!cancelled) setPolicyCatalogError(e instanceof Error ? e.message : "Failed to load");
      })
      .finally(() => {
        if (!cancelled) setPolicyCatalogLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [policyInstallOpen, policyCatalog.length]);

  function openPolicyInstallModal() {
    setInstallFormError("");
    setPolicyCatalogError("");
    setSelectedCatalogTemplateId(null);
    setInstallPolicyId("");
    setPolicyInstallOpen(true);
  }

  async function submitInstallFromCatalog() {
    setInstallFormError("");
    const entry = policyCatalog.find((p) => p.id === selectedCatalogTemplateId);
    if (!entry) {
      setInstallFormError("Select a policy template.");
      return;
    }
    const pid = installPolicyId.trim() || entry.default_policy_id;
    if (!POLICY_SLUG_RE.test(pid)) {
      setInstallFormError("Policy ID must be a lowercase slug (3–64 characters).");
      return;
    }
    const yaml = renderCatalogInstallYaml(entry, vaultName, pid);
    setInstallSubmitLoading(true);
    try {
      const resp = await apiFetch(`${base}/policies`, {
        method: "POST",
        headers: { "Content-Type": "application/yaml" },
        body: yaml,
      });
      if (!resp.ok) {
        setInstallFormError(await readApiError(resp));
        return;
      }
      setPolicyInstallOpen(false);
      setSelectedCatalogTemplateId(null);
      await refresh();
    } finally {
      setInstallSubmitLoading(false);
    }
  }

  useEffect(() => {
    if (!policyEditor) return;
    let cancelled = false;
    (async () => {
      try {
        const sRes = await apiFetch(`${base}/services`);
        if (cancelled) return;
        if (sRes.ok) {
          const d = await sRes.json();
          setVaultServices(d.services ?? []);
        }
      } catch {
        /* optional */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [policyEditor, base]);

  function updatePolicyForm(updater: (f: PolicyFormState) => PolicyFormState) {
    setPolicyEditor((prev) => {
      if (!prev) return prev;
      return { ...prev, form: updater(prev.form), parseError: undefined };
    });
  }

  function onPolicyServiceChange(host: string) {
    if (!host) {
      setPolicyEditor((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          parseError: undefined,
          form: { ...prev.form, serviceHost: "", credentialKey: "*" },
        };
      });
      return;
    }
    const svc = vaultServices.find((s) => s.host === host);
    const cred = inferCredentialKeyForService(svc);
    setPolicyEditor((prev) => {
      if (!prev) return prev;
      return {
        ...prev,
        parseError: undefined,
        form: {
          ...prev.form,
          serviceHost: host,
          credentialKey: cred,
        },
      };
    });
  }

  function addPolicyRule() {
    updatePolicyForm((f) => ({
      ...f,
      rules: [
        ...f.rules,
        {
          id: `rule-${f.rules.length + 1}`,
          effect: "allow",
          methods: ["GET"],
          pathPatterns: "/**",
        },
      ],
    }));
  }

  function removePolicyRule(index: number) {
    updatePolicyForm((f) => ({
      ...f,
      rules: f.rules.filter((_, i) => i !== index),
    }));
  }

  function updateRule(index: number, patch: Partial<PolicyFormRule>) {
    updatePolicyForm((f) => ({
      ...f,
      rules: f.rules.map((r, i) => (i === index ? { ...r, ...patch } : r)),
    }));
  }

  function toggleRuleMethod(ruleIndex: number, method: string) {
    const up = method.toUpperCase();
    updatePolicyForm((f) => {
      const rules = f.rules.map((r, i) => {
        if (i !== ruleIndex) return r;
        const has = r.methods.some((m) => m.toUpperCase() === up);
        const methods = has
          ? r.methods.filter((m) => m.toUpperCase() !== up)
          : [...r.methods, up];
        return { ...r, methods };
      });
      return { ...f, rules };
    });
  }

  async function savePolicyEditor() {
    if (!policyEditor || policyEditor.parseError) return;
    const msg = validatePolicyForm(
      policyEditor.form,
      policyEditor.mode,
      policyEditor.lockedPolicyId,
    );
    if (msg) {
      setPolicySaveError(msg);
      return;
    }
    const yaml = buildPolicyYAML(vaultName, policyEditor.form);
    await submitPolicyYaml(yaml);
  }

  async function submitPolicyYaml(yaml: string) {
    setPolicySaveError("");
    setPolicySaveLoading(true);
    try {
      const resp = await apiFetch(`${base}/policies`, {
        method: "POST",
        headers: { "Content-Type": "application/yaml" },
        body: yaml,
      });
      if (!resp.ok) {
        setPolicySaveError(await readApiError(resp));
        return;
      }
      setPolicyEditor(null);
      await refresh();
    } finally {
      setPolicySaveLoading(false);
    }
  }

  async function patchPolicyEnabled(nextEnabled: boolean) {
    if (!policySheet) return;
    const id = policySheet.id;
    const prev = policySheet;
    setPolicyDetailError("");
    setPolicyDetailPatchLoading(true);
    setPolicySheet({ ...policySheet, enabled: nextEnabled });
    try {
      const resp = await apiFetch(`${base}/policies/${encodeURIComponent(id)}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled: nextEnabled }),
      });
      if (!resp.ok) {
        setPolicySheet(prev);
        setPolicyDetailError(await readApiError(resp));
        return;
      }
      const data = (await resp.json()) as Record<string, unknown>;
      setPolicySheet(policyFromAPIPayload(data));
      await refresh();
    } catch {
      setPolicySheet(prev);
      setPolicyDetailError("Network error.");
    } finally {
      setPolicyDetailPatchLoading(false);
    }
  }

  async function openGrantModal() {
    setGrantFormError("");
    setGrantAgentName("");
    setGrantPolicyId(policies[0]?.id ?? "");
    setGrantPolicyVersion("");
    setGrantExpiresLocal("");
    setGrantModalOpen(true);
    try {
      const resp = await apiFetch(`${base}/agents`);
      if (resp.ok) {
        const data = await resp.json();
        setGrantAgents(
          (data.agents ?? []).map((a: { name: string }) => ({ name: a.name })),
        );
      } else {
        setGrantAgents([]);
      }
    } catch {
      setGrantAgents([]);
    }
  }

  async function submitGrant() {
    setGrantFormError("");
    const policyId = grantPolicyId.trim();
    if (!policyId) {
      setGrantFormError("Select a policy.");
      return;
    }
    const agent = grantAgentName.trim();
    if (!agent) {
      setGrantFormError("Select an agent.");
      return;
    }

    const body: Record<string, unknown> = {
      subject_type: "agent",
      subject_name: agent,
      policy_id: policyId,
    };

    const ver = grantPolicyVersion.trim();
    if (ver !== "") {
      const n = parseInt(ver, 10);
      if (Number.isNaN(n) || n < 1) {
        setGrantFormError("Policy version must be a positive integer, or leave empty for latest.");
        return;
      }
      body.policy_version = n;
    }

    if (grantExpiresLocal) {
      const d = new Date(grantExpiresLocal);
      if (Number.isNaN(d.getTime())) {
        setGrantFormError("Invalid expiry date.");
        return;
      }
      body.expires_at = d.toISOString();
    }

    setGrantSubmitLoading(true);
    try {
      const resp = await apiFetch(`${base}/grants`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      if (!resp.ok) {
        setGrantFormError(await readApiError(resp));
        return;
      }
      setGrantModalOpen(false);
      await refresh();
    } finally {
      setGrantSubmitLoading(false);
    }
  }

  async function confirmRevokeGrant() {
    if (!revokeGrantId) return;
    setRevokeLoading(true);
    try {
      const resp = await apiFetch(`${base}/grants/${encodeURIComponent(revokeGrantId)}`, {
        method: "DELETE",
      });
      if (!resp.ok) {
        setError(await readApiError(resp));
        return;
      }
      setRevokeGrantId(null);
      setGrantSheet(null);
      await refresh();
    } finally {
      setRevokeLoading(false);
    }
  }

  useEffect(() => {
    if (!policySheet) {
      setVersions([]);
      return;
    }
    let cancelled = false;
    setVersionsLoading(true);
    apiFetch(`${base}/policies/${encodeURIComponent(policySheet.id)}/versions`)
      .then(async (resp) => {
        if (!resp.ok) return;
        const data = await resp.json();
        if (!cancelled) setVersions(data.versions ?? []);
      })
      .finally(() => {
        if (!cancelled) setVersionsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [policySheet, base]);

  const grantCountByPolicyId = useMemo(() => {
    const m = new Map<string, number>();
    for (const g of grants) {
      m.set(g.policy_id, (m.get(g.policy_id) ?? 0) + 1);
    }
    return m;
  }, [grants]);

  const policyColumns: Column<PolicySummary>[] = [
    {
      key: "id",
      header: "Policy",
      render: (p) => (
        <span className="font-mono text-sm text-text">{p.id}</span>
      ),
    },
    {
      key: "version",
      header: "Version",
      render: (p) => <span className="text-text-muted text-sm">v{p.version}</span>,
    },
    {
      key: "grants",
      header: "Grants",
      render: (p) => (
        <span className="text-sm text-text-muted tabular-nums">
          {grantCountByPolicyId.get(p.id) ?? 0}
        </span>
      ),
    },
    {
      key: "enabled",
      header: "Status",
      render: (p) => (
        <StatusBadge status={p.enabled ? "enabled" : "disabled"} />
      ),
    },
    {
      key: "description",
      header: "Description",
      render: (p) => (
        <span className="text-sm text-text-muted line-clamp-2 max-w-[240px]">
          {p.description || "—"}
        </span>
      ),
    },
    {
      key: "authored_at",
      header: "Updated",
      render: (p) => (
        <span className="text-sm text-text-dim">{timeAgo(p.authored_at)}</span>
      ),
    },
  ];

  const grantColumns: Column<GrantRow>[] = [
    {
      key: "id",
      header: "Grant",
      render: (g) => (
        <span className="font-mono text-xs text-text">{g.id}</span>
      ),
    },
    {
      key: "subject",
      header: "Subject",
      render: (g) => (
        <span className="text-sm text-text">
          {g.subject_type}:{g.subject_id.length > 12 ? `${g.subject_id.slice(0, 10)}…` : g.subject_id}
        </span>
      ),
    },
    {
      key: "policy",
      header: "Policy",
      render: (g) => (
        <span className="font-mono text-sm text-text-muted">
          {g.policy_id}@{g.policy_version || "latest"}
        </span>
      ),
    },
    {
      key: "state",
      header: "State",
      render: (g) =>
        g.revoked_at ? (
          <StatusBadge status="revoked" />
        ) : (
          <StatusBadge status="active" />
        ),
    },
    {
      key: "granted_at",
      header: "Granted",
      render: (g) => (
        <span className="text-sm text-text-dim">{timeAgo(g.granted_at)}</span>
      ),
    },
  ];

  if (loading) {
    return (
      <div className="w-full max-w-5xl px-6 py-8">
        <LoadingSpinner />
      </div>
    );
  }

  return (
    <div className="w-full max-w-5xl px-6 py-8">
      <header className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold text-text tracking-tight">
            Policies &amp; grants
          </h1>
          <p className="text-sm text-text-muted mt-1 max-w-2xl">
            Policies attach to a vault service (host) and the credential key name used in that
            service&apos;s auth config — not the secret value. Rotating a credential under the same
            key keeps the policy valid. Grants bind agents to policies. Requires vault member or
            admin; agents cannot author policies or grants.
          </p>
        </div>
        {!engineOff && panel === "grants" && (
          <div className="flex flex-wrap gap-2 shrink-0">
            <Button type="button" variant="secondary" onClick={openGrantModal}>
              New grant
            </Button>
          </div>
        )}
      </header>

      {error && <ErrorBanner message={error} className="mb-6" />}

      {engineOff && (
        <div className="mb-6 rounded-lg border border-border bg-bg/50 px-4 py-3 text-sm text-text-muted">
          Policy engine is not enabled on this server (management API returned 503).
        </div>
      )}

      <div className="flex gap-1 p-1 rounded-lg bg-bg/80 border border-border w-fit mb-6">
        <button
          type="button"
          onClick={() => setPanel("policies")}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            panel === "policies"
              ? "bg-surface text-text shadow-sm"
              : "text-text-muted hover:text-text"
          }`}
        >
          Policies
        </button>
        <button
          type="button"
          onClick={() => setPanel("grants")}
          className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
            panel === "grants"
              ? "bg-surface text-text shadow-sm"
              : "text-text-muted hover:text-text"
          }`}
        >
          Grants
        </button>
      </div>

      {panel === "policies" && (
        <>
          {policies.length === 0 && !engineOff ? (
            <EmptyState message='No policies yet. Install from the catalog below, use Custom policy, or agent-vault policies create.' />
          ) : policies.length > 0 ? (
            <DataTable
              columns={policyColumns}
              data={policies}
              rowKey={(p) => p.id}
              onRowClick={(p) => setPolicySheet(p)}
            />
          ) : null}
          {!engineOff && (
            <div className="mt-8 pt-6 border-t border-border">
              <p className="text-xs font-semibold uppercase tracking-wider text-text-dim mb-3">
                Add policy
              </p>
              <div className="flex flex-wrap items-center gap-3">
                <Button type="button" variant="secondary" onClick={openPolicyInstallModal}>
                  <svg
                    className="w-4 h-4 shrink-0"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden
                  >
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="7 10 12 15 17 10" />
                    <line x1="12" y1="15" x2="12" y2="3" />
                  </svg>
                  Install policy
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    setPolicySaveError("");
                    setPolicyEditor({ mode: "create", form: defaultPolicyForm() });
                  }}
                >
                  <svg
                    className="w-4 h-4 shrink-0"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden
                  >
                    <line x1="12" y1="5" x2="12" y2="19" />
                    <line x1="5" y1="12" x2="19" y2="12" />
                  </svg>
                  Custom policy
                </Button>
              </div>
              <p className="text-sm text-text-muted mt-3 max-w-2xl">
                Install policy picks a read-only default from the built-in catalog (same idea as
                service templates). A future policy registry will let publishers share templates and
                others install them; today the list is shipped with the server.
              </p>
            </div>
          )}
        </>
      )}

      {panel === "grants" && (
        <>
          {grants.length === 0 && !engineOff ? (
            <EmptyState message='No grants yet. Use "New grant" above or agent-vault grants create.' />
          ) : grants.length > 0 ? (
            <DataTable
              columns={grantColumns}
              data={grants}
              rowKey={(g) => g.id}
              onRowClick={(g) => setGrantSheet(g)}
            />
          ) : null}
        </>
      )}

      <Sheet
        open={policySheet !== null}
        onClose={() => {
          setPolicySheet(null);
          setPolicyDetailError("");
        }}
        eyebrow="Policy"
        title={policySheet?.id ?? ""}
        widthClass="max-w-[720px]"
        headerExtra={
          policySheet && (
            <div className="flex flex-wrap items-center gap-2 mt-2">
              <StatusBadge status={policySheet.enabled ? "enabled" : "disabled"} />
              <span className="text-xs text-text-dim">
                v{policySheet.version} · {timeAgo(policySheet.authored_at)}
              </span>
            </div>
          )
        }
        footer={
          policySheet ? (
            <div className="flex flex-wrap items-center justify-end gap-2">
              {canAuthorPolicies ? (
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    setPolicySaveError("");
                    const parsed = policyFormFromYaml(policySheet.yaml_source);
                    if (!parsed.ok) {
                      setPolicyEditor({
                        mode: "version",
                        lockedPolicyId: policySheet.id,
                        form: defaultPolicyForm(),
                        parseError: parsed.error,
                      });
                    } else {
                      setPolicyEditor({
                        mode: "version",
                        lockedPolicyId: policySheet.id,
                        form: parsed.form,
                      });
                    }
                    setPolicySheet(null);
                  }}
                >
                  New version
                </Button>
              ) : null}
              <Button
                type="button"
                variant="secondary"
                onClick={() => downloadPolicyYaml(policySheet)}
              >
                <svg
                  className="w-4 h-4 shrink-0"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden
                >
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="7 10 12 15 17 10" />
                  <line x1="12" y1="15" x2="12" y2="3" />
                </svg>
                Download YAML
              </Button>
              <Button type="button" variant="secondary" disabled title="Coming soon">
                Publish
              </Button>
            </div>
          ) : undefined
        }
      >
        {policySheet && (() => {
          const parsedView = parsePolicyYamlForView(policySheet.yaml_source);
          const descriptionText =
            (policySheet.description && policySheet.description.trim()) ||
            (parsedView?.description?.trim() ?? "") ||
            "—";
          return (
            <div className="space-y-5">
              <dl className="text-sm space-y-3">
                <div>
                  <dt className="text-text-dim text-xs uppercase tracking-wide">Description</dt>
                  <dd className="text-text mt-0.5">{descriptionText}</dd>
                </div>
                <div>
                  <dt className="text-text-dim text-xs uppercase tracking-wide">Version</dt>
                  <dd className="font-mono text-text mt-0.5">v{policySheet.version}</dd>
                </div>
              </dl>

              <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border bg-bg/40 px-3 py-2.5">
                <div>
                  <div className="text-xs font-semibold text-text-dim uppercase tracking-wide">
                    Policy enabled
                  </div>
                  <p className="text-xs text-text-muted mt-0.5">
                    {policySheet.enabled
                      ? "Requests may match this policy when grants apply."
                      : "Disabled policies do not match new requests."}
                  </p>
                </div>
                {canAuthorPolicies ? (
                  <Toggle
                    checked={policySheet.enabled}
                    disabled={policyDetailPatchLoading}
                    ariaLabel="Policy enabled"
                    onChange={(next) => void patchPolicyEnabled(next)}
                  />
                ) : (
                  <span className="text-xs text-text-muted">
                    {policySheet.enabled ? "On" : "Off"}
                  </span>
                )}
              </div>
              {policyDetailError ? (
                <p className="text-sm text-danger">{policyDetailError}</p>
              ) : null}

              {!parsedView ? (
                <p className="text-sm text-text-muted">
                  Could not read policy scope or rules from this document. Use{" "}
                  <span className="font-mono">New version</span> to replace it if needed.
                </p>
              ) : (
                <>
                  <div>
                    <h3 className="text-xs font-semibold text-text-dim uppercase tracking-wider mb-2">
                      Service scope
                    </h3>
                    {parsedView.resources.length === 0 ? (
                      <p className="text-sm text-text-muted">No resources in document.</p>
                    ) : (
                      <ul className="space-y-2">
                        {parsedView.resources.map((res, i) => (
                          <li
                            key={`${res.service_host}-${res.credential_key}-${i}`}
                            className="rounded-lg border border-border bg-bg px-3 py-2 text-sm"
                          >
                            <div className="font-mono text-text">{res.service_host || "—"}</div>
                            <div className="text-xs text-text-muted mt-1">
                              Credential key:{" "}
                              <span className="font-mono text-text-dim">{res.credential_key || "—"}</span>
                            </div>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                  <div>
                    <h3 className="text-xs font-semibold text-text-dim uppercase tracking-wider mb-2">
                      Rules
                    </h3>
                    {parsedView.rules.length === 0 ? (
                      <p className="text-sm text-text-muted">No rules in document.</p>
                    ) : (
                      <ul className="space-y-3">
                        {parsedView.rules.map((rule) => {
                          const methodsLabel =
                            rule.methods.length === 0 ||
                            (rule.methods.length === 1 && rule.methods[0] === "*")
                              ? "Any method"
                              : rule.methods.join(", ");
                          return (
                            <li
                              key={rule.id}
                              className="rounded-lg border border-border bg-bg px-3 py-2.5 text-sm"
                            >
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="font-mono text-text">{rule.id || "(unnamed)"}</span>
                                <span
                                  className={`text-[11px] font-semibold uppercase px-2 py-0.5 rounded ${
                                    rule.effect === "deny"
                                      ? "bg-danger/15 text-danger"
                                      : "bg-success/15 text-success"
                                  }`}
                                >
                                  {rule.effect || "allow"}
                                </span>
                              </div>
                              <div className="text-xs text-text-muted mt-2">{methodsLabel}</div>
                              <div className="text-xs font-mono text-text-dim mt-1 break-all">
                                {rule.path_patterns.length > 0
                                  ? rule.path_patterns.join(", ")
                                  : "—"}
                              </div>
                            </li>
                          );
                        })}
                      </ul>
                    )}
                  </div>
                </>
              )}

              <details className="text-xs text-text-muted border border-border rounded-lg p-3">
                <summary className="cursor-pointer font-semibold text-text-dim uppercase tracking-wide select-none">
                  Version history and metadata
                </summary>
                <div className="mt-3 space-y-2 font-mono break-all">
                  {versionsLoading ? (
                    <p>Loading…</p>
                  ) : versions.length > 0 ? (
                    <ul className="space-y-1 max-h-32 overflow-y-auto">
                      {versions.map((v) => (
                        <li key={v.version}>
                          v{v.version}
                          {v.version === policySheet.version ? (
                            <span className="text-primary ml-2">(current)</span>
                          ) : null}
                          <span className="text-text-dim ml-2">{timeAgo(v.authored_at)}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p>No history</p>
                  )}
                  <div className="pt-2 border-t border-border space-y-1">
                    <div>
                      <span className="text-text-dim">content_hash </span>
                      {policySheet.content_hash}
                    </div>
                    {policySheet.parent_hash ? (
                      <div>
                        <span className="text-text-dim">parent_hash </span>
                        {policySheet.parent_hash}
                      </div>
                    ) : null}
                    <div>
                      <span className="text-text-dim">authored_by </span>
                      {policySheet.authored_by}
                    </div>
                  </div>
                </div>
              </details>
            </div>
          );
        })()}
      </Sheet>

      <Sheet
        open={grantSheet !== null}
        onClose={() => setGrantSheet(null)}
        eyebrow="Grant"
        title={grantSheet?.id ?? ""}
        widthClass="max-w-[520px]"
        headerExtra={
          grantSheet && (
            <div className="flex flex-wrap gap-2 mt-2">
              {grantSheet.revoked_at ? (
                <StatusBadge status="revoked" />
              ) : (
                <StatusBadge status="active" />
              )}
            </div>
          )
        }
        footer={
          grantSheet && !grantSheet.revoked_at ? (
            <button
              type="button"
              className="px-5 py-2.5 rounded-lg text-sm font-semibold border border-danger text-danger hover:bg-danger/10 transition-colors"
              onClick={() => setRevokeGrantId(grantSheet.id)}
            >
              Revoke grant
            </button>
          ) : undefined
        }
      >
        {grantSheet && (
          <dl className="text-sm space-y-3">
            <div>
              <dt className="text-text-dim text-xs uppercase tracking-wide">Subject</dt>
              <dd className="font-mono text-text mt-0.5">
                {grantSheet.subject_type}:{grantSheet.subject_id}
              </dd>
            </div>
            <div>
              <dt className="text-text-dim text-xs uppercase tracking-wide">Policy</dt>
              <dd className="font-mono text-text mt-0.5">
                {grantSheet.policy_id}@{grantSheet.policy_version || "latest"}
              </dd>
            </div>
            <div>
              <dt className="text-text-dim text-xs uppercase tracking-wide">Conditions</dt>
              <dd className="mt-0.5">
                <pre className="text-xs font-mono bg-bg border border-border rounded-lg p-3 overflow-x-auto text-text-muted">
                  {JSON.stringify(grantSheet.conditions ?? {}, null, 2)}
                </pre>
              </dd>
            </div>
            <div>
              <dt className="text-text-dim text-xs uppercase tracking-wide">Granted</dt>
              <dd className="text-text mt-0.5">
                {grantSheet.granted_at} ({timeAgo(grantSheet.granted_at)}) by{" "}
                {grantSheet.granted_by}
              </dd>
            </div>
            {grantSheet.expires_at && (
              <div>
                <dt className="text-text-dim text-xs uppercase tracking-wide">Expires</dt>
                <dd className="text-text mt-0.5">{grantSheet.expires_at}</dd>
              </div>
            )}
            {grantSheet.revoked_at && (
              <div>
                <dt className="text-text-dim text-xs uppercase tracking-wide">Revoked</dt>
                <dd className="text-text mt-0.5">
                  {grantSheet.revoked_at}
                  {grantSheet.revoked_by ? ` by ${grantSheet.revoked_by}` : ""}
                </dd>
              </div>
            )}
          </dl>
        )}
      </Sheet>

      <Sheet
        open={policyEditor !== null}
        onClose={() => !policySaveLoading && setPolicyEditor(null)}
        eyebrow={policyEditor?.mode === "create" ? "Create policy" : "New policy version"}
        title={
          policyEditor?.mode === "create"
            ? "Policy builder"
            : (policyEditor?.lockedPolicyId ?? "")
        }
        widthClass="max-w-[720px]"
        footer={
          policyEditor && (
            <>
              <Button
                type="button"
                variant="secondary"
                disabled={policySaveLoading}
                onClick={() => setPolicyEditor(null)}
              >
                Cancel
              </Button>
              <Button
                type="button"
                loading={policySaveLoading}
                disabled={!!policyEditor.parseError}
                onClick={() => savePolicyEditor()}
              >
                Save
              </Button>
            </>
          )
        }
      >
        {policyEditor && (
          <PolicyEditorBody
            editor={policyEditor}
            vaultServices={vaultServices}
            policySaveError={policySaveError}
            onPolicyServiceChange={onPolicyServiceChange}
            updatePolicyForm={updatePolicyForm}
            addPolicyRule={addPolicyRule}
            removePolicyRule={removePolicyRule}
            updateRule={updateRule}
            toggleRuleMethod={toggleRuleMethod}
          />
        )}
      </Sheet>

      <Modal
        open={policyInstallOpen}
        onClose={() => !installSubmitLoading && setPolicyInstallOpen(false)}
        title="Install policy"
        description="Choose a built-in template (read-only API access). Policy ID must be unique in this vault."
        footer={
          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="secondary"
              disabled={installSubmitLoading}
              onClick={() => setPolicyInstallOpen(false)}
            >
              Cancel
            </Button>
            <Button
              type="button"
              loading={installSubmitLoading}
              disabled={!selectedCatalogTemplateId}
              onClick={submitInstallFromCatalog}
            >
              Install
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          {policyCatalogLoading ? (
            <p className="text-sm text-text-muted py-6 text-center">Loading catalog…</p>
          ) : null}
          {policyCatalogError ? <ErrorBanner message={policyCatalogError} /> : null}
          {!policyCatalogLoading && !policyCatalogError && policyCatalog.length === 0 ? (
            <p className="text-sm text-text-muted">No templates available.</p>
          ) : null}
          {policyCatalog.length > 0 ? (
            <div className="grid gap-2 sm:grid-cols-2 max-h-[min(50vh,320px)] overflow-y-auto pr-1">
              {policyCatalog.map((e) => {
                const sel = selectedCatalogTemplateId === e.id;
                return (
                  <button
                    key={e.id}
                    type="button"
                    onClick={() => {
                      setSelectedCatalogTemplateId(e.id);
                      setInstallPolicyId(e.default_policy_id);
                      setInstallFormError("");
                    }}
                    className={`text-left rounded-xl border p-3 transition-colors ${
                      sel
                        ? "border-primary bg-primary/5 ring-2 ring-primary/30"
                        : "border-border bg-bg/40 hover:border-border-focus hover:bg-bg/60"
                    }`}
                  >
                    <div className="text-sm font-semibold text-text">{e.name}</div>
                    <div className="text-xs text-text-muted mt-1 line-clamp-2">{e.description}</div>
                    <div className="text-[11px] font-mono text-text-dim mt-2 truncate">
                      {e.service_host} · {e.suggested_credential_key}
                    </div>
                  </button>
                );
              })}
            </div>
          ) : null}
          {selectedCatalogTemplateId ? (
            <FormField
              label="Policy ID"
              helperText="Lowercase slug. Change it if this id already exists in the vault."
            >
              <input
                type="text"
                className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm font-mono text-text"
                value={installPolicyId}
                onChange={(e) => setInstallPolicyId(e.target.value.trim())}
                autoComplete="off"
              />
            </FormField>
          ) : null}
          {installFormError ? <p className="text-sm text-danger">{installFormError}</p> : null}
        </div>
      </Modal>

      <Modal
        open={revokeGrantId !== null}
        onClose={() => !revokeLoading && setRevokeGrantId(null)}
        title="Revoke grant?"
        description="This sets revoked_at on the grant. The change cannot be undone from the UI."
        footer={
          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="secondary"
              disabled={revokeLoading}
              onClick={() => setRevokeGrantId(null)}
            >
              Cancel
            </Button>
            <Button type="button" loading={revokeLoading} onClick={confirmRevokeGrant}>
              Revoke
            </Button>
          </div>
        }
      >
        {null}
      </Modal>

      <Modal
        open={grantModalOpen}
        onClose={() => !grantSubmitLoading && setGrantModalOpen(false)}
        title="New grant"
        description="Bind a vault agent to a policy (always-latest unless you pin a version below)."
        footer={
          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="secondary"
              disabled={grantSubmitLoading}
              onClick={() => setGrantModalOpen(false)}
            >
              Cancel
            </Button>
            <Button type="button" loading={grantSubmitLoading} onClick={submitGrant}>
              Create grant
            </Button>
          </div>
        }
      >
        <div className="space-y-4">
          {grantFormError && <p className="text-sm text-danger">{grantFormError}</p>}
          <FormField label="Agent">
            <Select
              value={grantAgentName}
              onChange={(e) => setGrantAgentName(e.target.value)}
            >
              <option value="">Select an agent…</option>
              {grantAgents.map((a) => (
                <option key={a.name} value={a.name}>
                  {a.name}
                </option>
              ))}
            </Select>
          </FormField>
          <FormField label="Policy">
            {policies.length === 0 ? (
              <p className="text-sm text-text-muted py-2">Create a policy in this vault first.</p>
            ) : (
              <Select
                value={grantPolicyId}
                onChange={(e) => setGrantPolicyId(e.target.value)}
              >
                {policies.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.id}
                    {p.description ? ` — ${p.description}` : ""}
                  </option>
                ))}
              </Select>
            )}
          </FormField>
          <details className="rounded-lg border border-border bg-bg/40 open:bg-bg/60">
            <summary className="cursor-pointer select-none text-sm font-medium text-text px-3 py-2.5">
              More options
            </summary>
            <div className="px-3 pb-4 pt-0 space-y-4 border-t border-border/60">
              <FormField
                label="Pin policy version (optional)"
                helperText="Leave empty to always use the latest policy version."
              >
                <input
                  type="text"
                  inputMode="numeric"
                  placeholder="e.g. 3"
                  className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text"
                  value={grantPolicyVersion}
                  onChange={(e) => setGrantPolicyVersion(e.target.value)}
                />
              </FormField>
              <FormField
                label="Expiry (optional)"
                helperText="Local time; stored in UTC on the server."
              >
                <input
                  type="datetime-local"
                  className="w-full rounded-lg border border-border bg-bg px-3 py-2 text-sm text-text"
                  value={grantExpiresLocal}
                  onChange={(e) => setGrantExpiresLocal(e.target.value)}
                />
              </FormField>
            </div>
          </details>
        </div>
      </Modal>
    </div>
  );
}
