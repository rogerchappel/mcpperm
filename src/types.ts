export type RiskLevel = "low" | "medium" | "high";

export type PermissionCategory =
  | "filesystem"
  | "shell"
  | "network"
  | "browser"
  | "credentials"
  | "messaging";

export interface ManifestTool {
  name: string;
  description?: string;
  inputSchema?: unknown;
  annotations?: Record<string, unknown>;
}

export interface ManifestResource {
  uri?: string;
  name?: string;
  description?: string;
}

export interface ManifestPrompt {
  name?: string;
  description?: string;
}

export interface NormalizedManifest {
  name: string;
  description?: string;
  capabilities: string[];
  tools: ManifestTool[];
  resources: ManifestResource[];
  prompts: ManifestPrompt[];
  raw: unknown;
}

export interface PermissionFinding {
  category: PermissionCategory;
  risk: RiskLevel;
  reasons: string[];
  evidence: string[];
}

export interface ToolProfile {
  name: string;
  description?: string;
  risk: RiskLevel;
  findings: PermissionFinding[];
}

export interface PermissionSummary {
  manifest: {
    name: string;
    description?: string;
  };
  risk: RiskLevel;
  categories: Record<PermissionCategory, RiskLevel | "none">;
  capabilities: string[];
  tools: ToolProfile[];
}

export interface PolicyPermission {
  allowed: boolean;
  risk: RiskLevel | "none";
  reasons: string[];
}

export interface PolicyTool {
  allowed: boolean;
  risk: RiskLevel;
  permissions: Record<PermissionCategory, PolicyPermission>;
  reviewRequired: boolean;
}

export interface PermissionPolicy {
  schemaVersion: "mcpperm.policy.v1";
  generatedAt: string;
  manifest: {
    name: string;
    description?: string;
  };
  defaultAction: "deny";
  reviewRequired: boolean;
  tools: Record<string, PolicyTool>;
}

export interface PolicyDrift {
  type:
    | "tool-added"
    | "tool-removed"
    | "permission-added"
    | "permission-removed"
    | "risk-changed"
    | "permission-risk-changed";
  risk: RiskLevel;
  message: string;
}
