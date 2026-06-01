import type {
  NormalizedManifest,
  PermissionCategory,
  PermissionFinding,
  PermissionSummary,
  RiskLevel,
  ToolProfile
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

const heuristics: Record<PermissionCategory, Array<{ risk: RiskLevel; pattern: RegExp; reason: string }>> = {
  filesystem: [
    { risk: "high", pattern: /\b(write|delete|remove|unlink|rename|chmod|chown|mkdir|rmdir)\b/i, reason: "mutates files or directories" },
    { risk: "medium", pattern: /\b(file|filesystem|directory|path|readfile|read_file|listdir|glob|workspace)\b/i, reason: "reads local filesystem paths" }
  ],
  shell: [
    { risk: "high", pattern: /\b(shell|exec|execute|command|terminal|process|spawn|bash|zsh|powershell|subprocess)\b/i, reason: "runs local commands or processes" }
  ],
  network: [
    { risk: "high", pattern: /\b(fetch|http|https|request|webhook|socket|download|upload|graphql|api)\b/i, reason: "connects to network services" },
    { risk: "medium", pattern: /\b(url|uri|endpoint|host|domain)\b/i, reason: "accepts network location inputs" }
  ],
  browser: [
    { risk: "medium", pattern: /\b(browser|page|tab|dom|click|screenshot|playwright|puppeteer|navigate)\b/i, reason: "controls or observes browser state" }
  ],
  credentials: [
    { risk: "high", pattern: /\b(secret|token|api[_ -]?key|credential|password|oauth|bearer|auth|login|session|cookie)\b/i, reason: "handles secrets or authentication material" }
  ],
  messaging: [
    { risk: "high", pattern: /\b(send|post|publish|reply|email|gmail|slack|discord|teams|sms|message|tweet)\b/i, reason: "can send messages or publish content" },
    { risk: "medium", pattern: /\b(inbox|notification|mention|thread|channel|dm)\b/i, reason: "reads messaging surfaces" }
  ]
};

function maxRisk(a: RiskLevel, b: RiskLevel): RiskLevel {
  return riskRank[a] >= riskRank[b] ? a : b;
}

export function combineRisk(levels: RiskLevel[]): RiskLevel {
  return levels.reduce<RiskLevel>((current, next) => maxRisk(current, next), "low");
}

function searchableText(value: unknown): string {
  if (value === undefined) {
    return "";
  }

  if (typeof value === "string") {
    return value;
  }

  try {
    return JSON.stringify(value);
  } catch {
    return "";
  }
}

export function profileTool(tool: NormalizedManifest["tools"][number]): ToolProfile {
  const haystack = [tool.name, tool.description, searchableText(tool.inputSchema), searchableText(tool.annotations)].join("\n");
  const findings: PermissionFinding[] = [];

  for (const category of categories) {
    const matches = heuristics[category].filter((heuristic) => heuristic.pattern.test(haystack));
    if (matches.length === 0) {
      continue;
    }

    const risk = combineRisk(matches.map((match) => match.risk));
    findings.push({
      category,
      risk,
      reasons: [...new Set(matches.map((match) => match.reason))],
      evidence: matches.map((match) => match.pattern.source)
    });
  }

  return {
    name: tool.name,
    description: tool.description,
    risk: findings.length > 0 ? combineRisk(findings.map((finding) => finding.risk)) : "low",
    findings
  };
}

export function inspectManifest(manifest: NormalizedManifest): PermissionSummary {
  const tools = manifest.tools.map(profileTool);
  const categorySummary = Object.fromEntries(categories.map((category) => [category, "none"])) as PermissionSummary["categories"];

  for (const tool of tools) {
    for (const finding of tool.findings) {
      const current = categorySummary[finding.category];
      categorySummary[finding.category] = current === "none" ? finding.risk : maxRisk(current, finding.risk);
    }
  }

  return {
    manifest: {
      name: manifest.name,
      description: manifest.description
    },
    risk: tools.length > 0 ? combineRisk(tools.map((tool) => tool.risk)) : "low",
    categories: categorySummary,
    capabilities: manifest.capabilities,
    tools
  };
}

export function formatSummary(summary: PermissionSummary): string {
  const lines = [
    `Manifest: ${summary.manifest.name}`,
    `Overall risk: ${summary.risk}`,
    "",
    "Permission categories:"
  ];

  for (const [category, risk] of Object.entries(summary.categories)) {
    lines.push(`- ${category}: ${risk}`);
  }

  lines.push("", "Tools:");

  for (const tool of summary.tools) {
    lines.push(`- ${tool.name}: ${tool.risk}`);
    for (const finding of tool.findings) {
      lines.push(`  - ${finding.category}: ${finding.risk} (${finding.reasons.join("; ")})`);
    }
  }

  if (summary.tools.length === 0) {
    lines.push("- none");
  }

  return `${lines.join("\n")}\n`;
}
