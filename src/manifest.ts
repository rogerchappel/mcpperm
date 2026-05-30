import { readFile } from "node:fs/promises";
import { basename } from "node:path";
import type { ManifestPrompt, ManifestResource, ManifestTool, NormalizedManifest } from "./types.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value : undefined;
}

function asRecordArray(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter(isRecord);
}

function extractCapabilities(raw: unknown): string[] {
  if (!isRecord(raw)) {
    return [];
  }

  const capabilities = raw.capabilities;
  if (Array.isArray(capabilities)) {
    return capabilities.filter((item): item is string => typeof item === "string");
  }

  if (isRecord(capabilities)) {
    return Object.keys(capabilities);
  }

  return [];
}

function extractTools(raw: unknown): ManifestTool[] {
  if (!isRecord(raw)) {
    return [];
  }

  const candidateLists = [
    raw.tools,
    isRecord(raw.server) ? raw.server.tools : undefined,
    isRecord(raw.manifest) ? raw.manifest.tools : undefined
  ];

  for (const candidate of candidateLists) {
    const records = asRecordArray(candidate);
    if (records.length > 0) {
      return records
        .map((tool) => ({
          name: asString(tool.name) ?? asString(tool.id) ?? "unnamed-tool",
          description: asString(tool.description),
          inputSchema: tool.inputSchema ?? tool.input_schema ?? tool.schema,
          annotations: isRecord(tool.annotations) ? tool.annotations : undefined
        }))
        .sort((a, b) => a.name.localeCompare(b.name));
    }
  }

  return [];
}

function extractResources(raw: unknown): ManifestResource[] {
  if (!isRecord(raw)) {
    return [];
  }

  return asRecordArray(raw.resources).map((resource) => ({
    uri: asString(resource.uri),
    name: asString(resource.name),
    description: asString(resource.description)
  }));
}

function extractPrompts(raw: unknown): ManifestPrompt[] {
  if (!isRecord(raw)) {
    return [];
  }

  return asRecordArray(raw.prompts).map((prompt) => ({
    name: asString(prompt.name),
    description: asString(prompt.description)
  }));
}

export function normalizeManifest(raw: unknown, sourceName = "inline-json"): NormalizedManifest {
  if (!isRecord(raw)) {
    throw new Error("Manifest must be a JSON object.");
  }

  const name =
    asString(raw.name) ??
    asString(raw.serverName) ??
    (isRecord(raw.server) ? asString(raw.server.name) : undefined) ??
    basename(sourceName);

  return {
    name,
    description: asString(raw.description),
    capabilities: extractCapabilities(raw).sort(),
    tools: extractTools(raw),
    resources: extractResources(raw),
    prompts: extractPrompts(raw),
    raw
  };
}

export async function readJsonInput(input: string): Promise<{ raw: unknown; sourceName: string }> {
  const trimmed = input.trim();

  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    return { raw: JSON.parse(trimmed) as unknown, sourceName: "inline-json" };
  }

  const contents = await readFile(input, "utf8");
  return { raw: JSON.parse(contents) as unknown, sourceName: input };
}
