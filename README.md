# Docker Scout AI-BOM

Discovers the **AI composition** of a container image, a source repository, or
the models managed by Docker Model Runner, and emits it as a CycloneDX **AI-BOM**.

A traditional SBOM inventories software packages and dependencies. An AI-BOM
inventories the **AI components** those packages don't capture: models,
frameworks, agents, and MCP servers. This is about **composition and inventory**
- *what AI is in here?* - for provenance, licensing, and governance (e.g. EU AI
Act evidence). It is **not** a vulnerability scanner.

It surfaces components no one registered - models baked into an image, `agents.yaml`
shipped inside a dependency, MCP servers declared in a config - that manual
inventories miss.

## What it discovers

| Category | Source |
|----------|--------|
| **Models** | Docker Model Runner artefacts (GGUF); weight files baked into an image (`.gguf`, `.safetensors`, `.onnx`, `.pt/.pth`, `.h5`, `.ckpt`, `.npz`, …) |
| **Datasets** | `.parquet`, `.arrow`, `.tfrecord`, `.feather`, `dataset_info.json`, … |
| **Frameworks** | AI libraries among the SBOM packages (`torch`, `transformers`, `langchain`, `crewai`, `openai`, `anthropic`, `mcp`, …) |
| **Agents** | Agent configuration files (`crew.yaml`, `agents.yaml`, `langgraph.json`, …) |
| **MCP servers** | Servers declared in `.mcp.json` / `claude_desktop_config.json` |
| **Inference providers** | Hosted APIs signalled by declared env vars (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_HOST`, …) - the remote model your code calls |
| **Prompts** | System prompts and prompt templates (`system_prompt.txt`, `*.prompt`, `*.jinja`, files under `prompts/`) |

Every component is tagged with an `aibom:category` property. Provider detection
records only the env var **name** and any endpoint URL - never the secret value.

## Build

```sh
go build -o aibom-scout .
```

## Usage

Three modes. Flags come before positional arguments.

```sh
# AI composition of a container image (Docker Scout SBOM + AI discovery)
./aibom-scout image -o aibom.cdx.json myorg/my-app:latest

# Docker Model Runner artefacts - all local models, or a single one
./aibom-scout model -o models.cdx.json
./aibom-scout model -o smollm2.cdx.json smollm2

# AI called by source code - imports and model references in a repo
./aibom-scout source -o code.cdx.json ./my-repo
```

The `source` mode scans `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs`
files for AI SDK imports (OpenAI, Anthropic, LangChain, CrewAI, MCP, …) and
model identifiers (`model="gpt-4o"`), skipping `node_modules`, `.venv`, etc.
Each component records the files it was found in.

| Flag | Mode | Default | Purpose |
|------|------|---------|---------|
| `-o` | all | stdout | write the AI-BOM here |
| `-max-hash-bytes` | image | 512 MiB | skip SHA-256 for files larger than this (`0` = always hash) |

## Example

```
$ ./aibom-scout image myorg/my-app:latest
AI-BOM: 6 models, 5 datasets, 8 frameworks, 3 agents, 2 MCP servers, 2 providers, 4 prompts
```

Docker Model Runner models become CycloneDX `machine-learning-model` components
with a model card (architecture) and format/quantization/parameters metadata:

```json
{
  "type": "machine-learning-model",
  "name": "ai/smollm2",
  "version": "360M-Q4_K_M",
  "modelCard": { "modelParameters": { "architectureFamily": "llama" } },
  "properties": [
    { "name": "aibom:category", "value": "model" },
    { "name": "aibom:source",   "value": "docker-model-runner" },
    { "name": "aibom:format",   "value": "gguf" }
  ]
}
```
