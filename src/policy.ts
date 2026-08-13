import type {
  PermissionCategory,
  PermissionPolicy,
  PermissionSummary,
  PolicyDrift,
  PolicyPermission,
  PolicyTool,
  RiskLevel
} from "./types.js";

const categories: PermissionCategory[] = [
  "filesystem",
  "shell",
  "network",
  "browser",
  "credentials",
  "messaging"
];

const riskRank: Record<RiskLevel, number> = {
  low: 1,
  medium: 2,
  high: 3
};

function emptyPermission(): PolicyPermission {
  return {
    allowed: false,
    risk: "none",
    reasons: []
  };
}

export function generatePolicy(summary: PermissionSummary, generatedAt = new Date().toISOString()): PermissionPolicy {
  const tools: Record<string, PolicyTool> = {};
  const seenToolNames = new Set<string>();

  for (const tool of summary.tools) {
    if (seenToolNames.has(tool.name)) {
      throw new Error(`Permission summary tool names must be unique; duplicate name "${tool.name}".`);
    }
    seenToolNames.add(tool.name);

    const permissions = Object.fromEntries(categories.map((category) => [category, emptyPermission()])) as PolicyTool["permissions"];

    for (const finding of tool.findings) {
      permissions[finding.category] = {
        allowed: true,
        risk: finding.risk,
        reasons: finding.reasons
      };
    }

    tools[tool.name] = {
      allowed: true,
      risk: tool.risk,
      permissions,
      reviewRequired: tool.risk === "high"
    };
  }

  return {
    schemaVersion: "mcpperm.policy.v1",
    generatedAt,
    manifest: summary.manifest,
    defaultAction: "deny",
    reviewRequired: summary.risk === "high",
    tools
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireObject(value: unknown, path: string): Record<string, unknown> {
  if (!isObject(value)) {
    throw new Error(`${path} must be a JSON object.`);
  }
  return value;
}

function requireBoolean(value: unknown, path: string): void {
  if (typeof value !== "boolean") {
    throw new Error(`${path} must be a boolean.`);
  }
}

function requireRisk(value: unknown, path: string, allowNone: boolean): void {
  const values = allowNone ? ["none", "low", "medium", "high"] : ["low", "medium", "high"];
  if (!values.includes(value as string)) {
    throw new Error(`${path} must be one of ${values.join(", ")}.`);
  }
}

function readPolicy(value: unknown, label: "Old policy" | "New policy"): PermissionPolicy {
  const policy = requireObject(value, label);
  if (policy.schemaVersion !== "mcpperm.policy.v1") {
    throw new Error(`${label} must use schemaVersion mcpperm.policy.v1.`);
  }
  if (typeof policy.generatedAt !== "string") {
    throw new Error(`${label} generatedAt must be a string.`);
  }

  const manifest = requireObject(policy.manifest, `${label} manifest`);
  if (typeof manifest.name !== "string" || manifest.name.trim() === "") {
    throw new Error(`${label} manifest.name must be a non-empty string.`);
  }
  if (manifest.description !== undefined && typeof manifest.description !== "string") {
    throw new Error(`${label} manifest.description must be a string when provided.`);
  }
  if (policy.defaultAction !== "deny") {
    throw new Error(`${label} defaultAction must be "deny".`);
  }
  requireBoolean(policy.reviewRequired, `${label} reviewRequired`);

  const tools = requireObject(policy.tools, `${label} tools`);
  for (const [toolName, toolValue] of Object.entries(tools)) {
    if (toolName.trim() === "") {
      throw new Error(`${label} tool names must be non-empty strings.`);
    }
    const toolPath = `${label} tools.${toolName}`;
    const tool = requireObject(toolValue, toolPath);
    requireBoolean(tool.allowed, `${toolPath}.allowed`);
    requireRisk(tool.risk, `${toolPath}.risk`, false);
    requireBoolean(tool.reviewRequired, `${toolPath}.reviewRequired`);

    const permissions = requireObject(tool.permissions, `${toolPath}.permissions`);
    for (const category of categories) {
      const permissionPath = `${toolPath}.permissions.${category}`;
      const permission = requireObject(permissions[category], permissionPath);
      requireBoolean(permission.allowed, `${permissionPath}.allowed`);
      requireRisk(permission.risk, `${permissionPath}.risk`, true);
      if (!Array.isArray(permission.reasons) || !permission.reasons.every((reason) => typeof reason === "string")) {
        throw new Error(`${permissionPath}.reasons must be an array of strings.`);
      }
    }
  }

  return policy as unknown as PermissionPolicy;
}

function driftRisk(oldRisk: RiskLevel | "none", newRisk: RiskLevel | "none"): RiskLevel {
  if (newRisk === "none") {
    return "low";
  }

  if (oldRisk === "none") {
    return newRisk;
  }

  return riskRank[newRisk] >= riskRank[oldRisk] ? newRisk : "low";
}

export function diffPolicies(oldValue: unknown, newValue: unknown): PolicyDrift[] {
  const oldPolicy = readPolicy(oldValue, "Old policy");
  const newPolicy = readPolicy(newValue, "New policy");
  const drifts: PolicyDrift[] = [];
  const toolNames = [...new Set([...Object.keys(oldPolicy.tools), ...Object.keys(newPolicy.tools)])].sort();

  for (const toolName of toolNames) {
    const oldTool = oldPolicy.tools[toolName];
    const newTool = newPolicy.tools[toolName];

    if (!oldTool && newTool) {
      drifts.push({
        type: "tool-added",
        risk: newTool.risk,
        message: `Tool added: ${toolName} (${newTool.risk})`
      });
      continue;
    }

    if (oldTool && !newTool) {
      drifts.push({
        type: "tool-removed",
        risk: "low",
        message: `Tool removed: ${toolName}`
      });
      continue;
    }

    if (!oldTool || !newTool) {
      continue;
    }

    if (oldTool.risk !== newTool.risk) {
      drifts.push({
        type: "risk-changed",
        risk: driftRisk(oldTool.risk, newTool.risk),
        message: `Tool risk changed: ${toolName} ${oldTool.risk} -> ${newTool.risk}`
      });
    }

    for (const category of categories) {
      const oldPermission = oldTool.permissions[category] ?? emptyPermission();
      const newPermission = newTool.permissions[category] ?? emptyPermission();

      if (!oldPermission.allowed && newPermission.allowed) {
        drifts.push({
          type: "permission-added",
          risk: newPermission.risk === "none" ? "low" : newPermission.risk,
          message: `Permission added: ${toolName} ${category} (${newPermission.risk})`
        });
      }

      if (oldPermission.allowed && !newPermission.allowed) {
        drifts.push({
          type: "permission-removed",
          risk: "low",
          message: `Permission removed: ${toolName} ${category}`
        });
      }

      if (oldPermission.allowed && newPermission.allowed && oldPermission.risk !== newPermission.risk) {
        drifts.push({
          type: "permission-risk-changed",
          risk: driftRisk(oldPermission.risk, newPermission.risk),
          message: `Permission risk changed: ${toolName} ${category} ${oldPermission.risk} -> ${newPermission.risk}`
        });
      }
    }
  }

  return drifts;
}

export function formatPolicyDiff(drifts: PolicyDrift[]): string {
  if (drifts.length === 0) {
    return "No permission drift detected.\n";
  }

  return `${drifts.map((drift) => `- [${drift.risk}] ${drift.message}`).join("\n")}\n`;
}
