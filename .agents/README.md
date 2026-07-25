# AG Kit

AG Kit is a modular `.agents/` toolkit for routing software-engineering tasks to specialist agents, loading focused skills, and verifying changes with executable checks.

## Quick start

1. Copy the `.agents/` directory into a project root.
2. Read `.agents/rules/core-protocol.md` and `.agents/memory/MEMORY.md` at session start.
3. Route work through the matching agent and load only the relevant skill sections.
4. Validate changes before completion:

```bash
python .agents/scripts/checklist.py .
```

For release verification:

```bash
python .agents/scripts/verify_all.py . --url http://localhost:3000
```

To verify AG Kit itself after editing agents, skills, workflows, rules, scripts, or links:

```bash
python .agents/scripts/generate_manifest.py
python .agents/scripts/dependency_graph.py
python .agents/scripts/validate_kit.py
```

Use `--check` with the first two commands in CI to detect stale generated files without rewriting them.

## Core concepts

- **Agents** define role, boundaries, tools, SemVer, and skill dependencies.
- **Skills** contain selectively loaded domain knowledge, SemVer contracts, and optional executable scripts.
- **Rules** define workspace-wide precedence and routing behavior.
- **Workflows** provide reusable slash-command procedures.
- **Memory** stores durable project conventions and decisions.
- **Registry and lock files** make dependencies machine-readable and detect drift.
- **Runtime scripts** turn guidance into repeatable evidence.

## Configuration

`mcp_config.json` is valid JSON. Replace `YOUR_API_KEY` before enabling the Context7 MCP server and keep the real credential outside version control whenever your runtime supports environment-based secret injection.

## Documentation

- [Architecture and inventory](ARCHITECTURE.md)
- [Generated dependency graph](DEPENDENCY_GRAPH.md)
- [Runtime scripts](scripts/README.md)
- [Toolkit change history](CHANGELOG.md)
- [Repository change history](../CHANGELOG.md)
- [Quick routing reference](rules/quick-reference.md)
