# MCPPerm PRD

Status: in-progress

## Summary

MCPPerm is a local CLI that reads MCP server/tool manifests and proposes a least-privilege permission profile. It highlights tools that imply filesystem, shell, network, browser, credential, or messaging access and emits a reviewable policy file that humans can edit before use.

## Why now

MCP adoption has grown across agent clients, and recent security reporting has focused on malicious servers, marketplace distribution, and tool-boundary confusion. Developers need a deterministic preflight for "what powers does this server appear to expose?" before attaching it to an agent.

Sources/inspiration:

- MCP security reporting in April 2026 from OX Security, Tom's Hardware, and TechRadar.
- Prompt-injection and tool-poisoning research across MCP clients: https://arxiv.org/abs/2603.21642
- Existing repo garden security tools such as `mcpseal`; MCPPerm is specifically a permission profiler and policy generator.

## Users

- Developers reviewing MCP server configs.
- Agent operators curating local MCP toolboxes.
- Security reviewers who want a low-friction manifest diff before enabling tools.

## MVP

- CLI commands:
  - `mcpperm inspect <manifest-or-json>` prints a permission summary.
  - `mcpperm policy <manifest-or-json>` writes a least-privilege JSON policy.
  - `mcpperm diff <old-policy> <new-policy>` explains permission drift.
- Heuristics based on tool names, descriptions, input schemas, and declared capabilities.
- JSON fixtures for benign docs tools, filesystem tools, shell tools, and messaging tools.
- Exit code option for high-risk tools.
- README with practical MCP review workflow.

## Non-goals

- No live MCP connection in V1.
- No marketplace crawler.
- No guarantee that a manifest is truthful.

## Success criteria

- Fixture manifests produce stable permission profiles.
- High-risk tools are clearly called out with reasons.
- Policy diff catches capability expansion.

