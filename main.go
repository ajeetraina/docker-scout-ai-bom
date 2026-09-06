// Command aibom-scout turns a Docker Scout SBOM into an AI-BOM.
//
// Docker Scout's `docker scout sbom` only enumerates OS and language packages;
// it has no notion of model weights, datasets, or other AI artefacts. This tool
// closes that gap: it takes Scout's CycloneDX output as the software baseline,
// scans the image filesystem for AI artefacts, and injects them as first-class
// CycloneDX `machine-learning-model` / `data` components — producing a single
// merged AI-BOM, exactly the "extend, don't replace the SBOM" model.
//
// Usage:
//
//	aibom-scout <image[:tag]> [-o out.cdx.json]
package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

func main() {
	out := flag.String("o", "", "write merged AI-BOM here (default: stdout)")
	maxHash := flag.Int64("max-hash-bytes", 512<<20, "skip SHA-256 for files larger than this (0 = always hash)")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: aibom-scout <image[:tag]> [-o out.cdx.json]")
		os.Exit(2)
	}
	image := flag.Arg(0)

	// 1. Software baseline: hand the CycloneDX SBOM off to Docker Scout.
	bom, err := scoutSBOM(image)
	if err != nil {
		fatalf("docker scout sbom: %v", err)
	}

	// 2. AI layer: scan the image's flattened filesystem for AI artefacts.
	artefacts, err := scanImage(image, *maxHash)
	if err != nil {
		fatalf("scan image: %v", err)
	}

	// 3. Merge the AI components into the software SBOM.
	comps := append(bomComponents(bom), artefacts...)
	bom.Components = &comps
	annotateAIBOM(bom, len(artefacts))

	// 4. Emit the merged AI-BOM.
	w := os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fatalf("create %s: %v", *out, err)
		}
		defer f.Close()
		w = f
	}
	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.Encode(bom); err != nil {
		fatalf("encode: %v", err)
	}
	fmt.Fprintf(os.Stderr, "AI-BOM: %d software + %d AI components\n", len(comps)-len(artefacts), len(artefacts))
}

// scoutSBOM runs `docker scout sbom --format cyclonedx` and decodes the result.
func scoutSBOM(image string) (*cdx.BOM, error) {
	cmd := exec.Command("docker", "scout", "sbom", "--format", "cyclonedx", image)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	bom := new(cdx.BOM)
	decErr := cdx.NewBOMDecoder(stdout, cdx.BOMFileFormatJSON).Decode(bom)
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	if decErr != nil {
		return nil, fmt.Errorf("decode cyclonedx: %w", decErr)
	}
	return bom, nil
}

// scanImage flattens the image via `docker create` + `docker export` and walks
// the resulting tar stream, classifying AI artefacts without unpacking to disk.
func scanImage(image string, maxHash int64) ([]cdx.Component, error) {
	id, err := exec.Command("docker", "create", image).Output()
	if err != nil {
		return nil, fmt.Errorf("docker create: %w", err)
	}
	cid := strings.TrimSpace(string(id))
	defer exec.Command("docker", "rm", "-f", cid).Run()

	cmd := exec.Command("docker", "export", cid)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var comps []cdx.Component
	tr := tar.NewReader(stdout)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		kind, matched := classify(hdr.Name)
		if !matched {
			continue
		}
		digest := ""
		if maxHash == 0 || hdr.Size <= maxHash {
			h := sha256.New()
			if _, err := io.Copy(h, tr); err != nil {
				return nil, err
			}
			digest = hex.EncodeToString(h.Sum(nil))
		}
		comps = append(comps, aiComponent(kind, hdr.Name, hdr.Size, digest))
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	return comps, nil
}

// classify decides whether a path is an AI artefact and, if so, whether it is a
// model or a dataset. Rules favour high-signal extensions to limit false hits.
func classify(name string) (cdx.ComponentType, bool) {
	base := strings.ToLower(path.Base(name))
	ext := path.Ext(base)

	modelExt := map[string]bool{
		".safetensors": true, ".gguf": true, ".ggml": true, ".onnx": true,
		".pt": true, ".pth": true, ".h5": true, ".pb": true, ".tflite": true,
		".mlmodel": true, ".ckpt": true, ".npz": true, ".ort": true,
	}
	modelFile := map[string]bool{
		"pytorch_model.bin": true, "model.bin": true, "config.json": true,
		"tokenizer.json": true, "tokenizer_config.json": true,
		"generation_config.json": true, "adapter_model.bin": true,
	}
	dataExt := map[string]bool{
		".parquet": true, ".arrow": true, ".tfrecord": true, ".feather": true,
	}
	dataFile := map[string]bool{
		"dataset_info.json": true, "dataset_infos.json": true,
	}

	switch {
	case modelExt[ext] || modelFile[base]:
		return cdx.ComponentTypeMachineLearningModel, true
	case dataExt[ext] || dataFile[base]:
		return cdx.ComponentTypeData, true
	default:
		return "", false
	}
}

func aiComponent(kind cdx.ComponentType, name string, size int64, digest string) cdx.Component {
	props := []cdx.Property{
		{Name: "aibom:source", Value: "image-filesystem-scan"},
		{Name: "aibom:path", Value: "/" + name},
		{Name: "aibom:size-bytes", Value: fmt.Sprintf("%d", size)},
	}
	c := cdx.Component{
		Type:       kind,
		Name:       path.Base(name),
		BOMRef:     "aibom:" + digestOrPath(digest, name),
		Properties: &props,
	}
	if digest != "" {
		c.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: digest}}
	}
	return c
}

func digestOrPath(digest, name string) string {
	if digest != "" {
		return digest
	}
	return strings.ReplaceAll(name, "/", "_")
}

func bomComponents(bom *cdx.BOM) []cdx.Component {
	if bom.Components == nil {
		return nil
	}
	return *bom.Components
}

func annotateAIBOM(bom *cdx.BOM, aiCount int) {
	if bom.Metadata == nil {
		bom.Metadata = &cdx.Metadata{}
	}
	props := []cdx.Property{
		{Name: "aibom:generator", Value: "aibom-scout"},
		{Name: "aibom:ai-components", Value: fmt.Sprintf("%d", aiCount)},
	}
	if bom.Metadata.Properties != nil {
		props = append(*bom.Metadata.Properties, props...)
	}
	bom.Metadata.Properties = &props
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
