# Agent red-team lab (opt-in)

This directory is a deterministic fixture for Skill/MCP inventory review. It is
not a production gate and it never sends repository source off the machine.

Run locally:

```bash
python scripts/ai_inventory.py fixtures/labs/agent-redteam --json
```

Do not point this lab at live credentials, production MCP servers, or a model
API. Prompt-injection text here is inert documentation for the inventory.
