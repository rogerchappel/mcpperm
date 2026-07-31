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

function readPolicy(value: unknown): PermissionPolicy {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("Policy must be a JSON object.");
  }

  const policy = value as PermissionPolicy;
  if (policy.schemaVersion !== "mcpperm.policy.v1" || typeof policy.tools !== "object" || policy.tools === null) {
    throw new Error("Policy must use schemaVersion mcpperm.policy.v1.");
  }

  return policy;
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
  const oldPolicy = readPolicy(oldValue);
  const newPolicy = readPolicy(newValue);
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
