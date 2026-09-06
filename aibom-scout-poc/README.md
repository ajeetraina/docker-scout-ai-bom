# aibom-scout-poc

Turns a **Docker Scout SBOM into an AI-BOM**.

`docker scout sbom` enumerates OS and language packages. This tool takes that
CycloneDX output as the software baseline, scans the image filesystem for AI
artefacts, and adds them as CycloneDX `machine-learning-model` / `data`
components — one merged AI-BOM that extends the SBOM.

## How it works

1. Runs `docker scout sbom --format cyclonedx <image>` for the software baseline.
2. Flattens the image (`docker create` + `docker export`) and walks the tar stream.
3. Classifies AI artefacts:
   - **Models**: `.safetensors`, `.gguf`, `.onnx`, `.pt/.pth`, `.h5`, `.pb`,
     `.tflite`, `.mlmodel`, `.ckpt`, `.npz`, `config.json`, `tokenizer.json`, …
   - **Datasets**: `.parquet`, `.arrow`, `.tfrecord`, `.feather`, `dataset_info.json`, …
4. Emits the merged AI-BOM with SHA-256, path, and size for each artefact.

## Build

```sh
go build -o aibom-scout-poc .
```

## Usage

Flags come before the image argument:

```sh
./aibom-scout-poc -o aibom.cdx.json myorg/my-model-image:latest
```

| Flag | Default | Purpose |
|------|---------|---------|
| `-o` | stdout | write the merged AI-BOM here |
| `-max-hash-bytes` | 512 MiB | skip SHA-256 for files larger than this (`0` = always hash) |

## Example

```
AI-BOM: 17 software + 4 AI components
```

```json
[
  { "type": "machine-learning-model", "name": "model.safetensors", "path": "/models/llama/model.safetensors" },
  { "type": "machine-learning-model", "name": "config.json",       "path": "/models/llama/config.json" },
  { "type": "data",                   "name": "train.parquet",     "path": "/data/train.parquet" },
  { "type": "data",                   "name": "dataset_info.json", "path": "/data/dataset_info.json" }
]
```
