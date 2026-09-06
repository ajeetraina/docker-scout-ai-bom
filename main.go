// Command aibom-scout discovers the AI composition of a container image or of
// the models managed by Docker Model Runner, and emits it as a CycloneDX AI-BOM.
//
// This is about COMPOSITION, not vulnerabilities: an AI-BOM answers "what AI is
// in here?" — models, frameworks, agents, and MCP servers — for inventory,
// provenance, licensing, and governance. It is not a CVE scanner.
//
// Two modes:
//
//	aibom-scout image <image[:tag]>   # AI composition of a container image
//	aibom-scout model [model]         # Docker Model Runner artefact(s)
//
// The image mode uses `docker scout sbom` as the software baseline, then
// discovers AI components the SBOM misses:
//
//   - models    — weight files baked into the image (.gguf, .safetensors, …)
//   - datasets  — dataset files (.parquet, .arrow, …)
//   - frameworks — AI libraries among the SBOM packages (torch, langchain, …)
//   - agents    — agent configuration files (crew.yaml, langgraph.json, …)
//   - mcp       — MCP servers declared in config files (.mcp.json, …)
//
// The model mode inspects Docker Model Runner artefacts (`docker model
// inspect` / `list --json`) — GGUF models distributed as OCI artefacts, not
// container images.
package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"sort"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

// AI-BOM component categories, recorded on every component as aibom:category.
const (
	catModel     = "model"
	catDataset   = "dataset"
	catFramework = "framework"
	catAgent     = "agent-config"
	catMCP       = "mcp-server"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "image":
		runImage(os.Args[2:])
	case "model":
		runModel(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  aibom-scout image <image[:tag]> [-o out.cdx.json]")
	fmt.Fprintln(os.Stderr, "  aibom-scout model [model]       [-o out.cdx.json]")
	os.Exit(2)
}

// runImage discovers the AI composition of a container image.
func runImage(argv []string) {
	fs := flag.NewFlagSet("image", flag.ExitOnError)
	out := fs.String("o", "", "write AI-BOM here (default: stdout)")
	maxHash := fs.Int64("max-hash-bytes", 512<<20, "skip SHA-256 for files larger than this (0 = always hash)")
	fs.Parse(argv)
	if fs.NArg() != 1 {
		usage()
	}
	image := fs.Arg(0)

	// Software baseline from Docker Scout.
	bom, err := scoutSBOM(image)
	if err != nil {
		fatalf("docker scout sbom: %v", err)
	}
	comps := bomComponents(bom)

	// Flag the AI frameworks already present among the SBOM packages.
	frameworks := tagFrameworks(comps)

	// Discover AI components the SBOM misses by walking the image filesystem.
	found, err := scanImage(image, *maxHash)
	if err != nil {
		fatalf("scan image: %v", err)
	}

	comps = append(comps, found...)
	bom.Components = &comps
	counts := countCategories(comps)
	counts[catFramework] = frameworks
	annotate(bom, counts)

	writeBOM(bom, *out)
	reportCounts(counts)
}

// runModel builds an AI-BOM from Docker Model Runner artefacts.
func runModel(argv []string) {
	fs := flag.NewFlagSet("model", flag.ExitOnError)
	out := fs.String("o", "", "write AI-BOM here (default: stdout)")
	fs.Parse(argv)

	var models []dmrModel
	var err error
	if fs.NArg() == 1 {
		models, err = dmrInspect(fs.Arg(0))
	} else {
		models, err = dmrList()
	}
	if err != nil {
		fatalf("docker model: %v", err)
	}

	comps := make([]cdx.Component, 0, len(models))
	for _, m := range models {
		comps = append(comps, m.component())
	}
	bom := cdx.NewBOM()
	bom.Components = &comps
	counts := countCategories(comps)
	annotate(bom, counts)

	writeBOM(bom, *out)
	reportCounts(counts)
}

// ---------------------------------------------------------------------------
// Docker Scout (software baseline)
// ---------------------------------------------------------------------------

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

// aiFrameworks are package names (pypi / npm) that signal AI/agent capability.
var aiFrameworks = map[string]bool{
	// inference / model libraries
	"torch": true, "tensorflow": true, "jax": true, "flax": true,
	"transformers": true, "diffusers": true, "accelerate": true, "peft": true,
	"sentence-transformers": true, "onnxruntime": true, "vllm": true,
	"llama-cpp-python": true, "ctransformers": true, "bitsandbytes": true,
	// SDKs
	"openai": true, "anthropic": true, "cohere": true, "ollama": true,
	"litellm": true, "@anthropic-ai/sdk": true, "@openai/openai": true,
	// agent / orchestration frameworks
	"langchain": true, "langchain-core": true, "langgraph": true,
	"llama-index": true, "llama-index-core": true, "llamaindex": true,
	"crewai": true, "autogen": true, "pyautogen": true, "autogen-agentchat": true,
	"smolagents": true, "haystack-ai": true, "dspy": true, "dspy-ai": true,
	"semantic-kernel": true, "instructor": true, "guidance": true,
	// MCP
	"mcp": true, "fastmcp": true, "@modelcontextprotocol/sdk": true,
}

// tagFrameworks marks SBOM components that are AI frameworks and returns a count.
func tagFrameworks(comps []cdx.Component) int {
	n := 0
	for i := range comps {
		name := strings.ToLower(comps[i].Name)
		if aiFrameworks[name] {
			addProp(&comps[i].Properties, "aibom:category", catFramework)
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Image filesystem scan (models, datasets, agents, MCP)
// ---------------------------------------------------------------------------

// scanImage flattens the image via `docker create` + `docker export` and walks
// the tar stream, discovering AI components without unpacking to disk.
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
		base := strings.ToLower(path.Base(hdr.Name))
		switch {
		case isMCPConfig(base):
			data := readCapped(tr, 1<<20)
			comps = append(comps, mcpComponents(hdr.Name, data)...)
		case isAgentConfig(base):
			comps = append(comps, agentComponent(hdr.Name))
		default:
			kind, cat, ok := classifyWeight(base)
			if !ok {
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
			comps = append(comps, weightComponent(kind, cat, hdr.Name, hdr.Size, digest))
		}
	}
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	return comps, nil
}

// classifyWeight matches model-weight and dataset files by extension/filename.
func classifyWeight(base string) (cdx.ComponentType, string, bool) {
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
		return cdx.ComponentTypeMachineLearningModel, catModel, true
	case dataExt[ext] || dataFile[base]:
		return cdx.ComponentTypeData, catDataset, true
	default:
		return "", "", false
	}
}

func weightComponent(kind cdx.ComponentType, cat, name string, size int64, digest string) cdx.Component {
	c := cdx.Component{
		Type:   kind,
		Name:   path.Base(name),
		BOMRef: "aibom:" + digestOrPath(digest, name),
	}
	addProp(&c.Properties, "aibom:category", cat)
	addProp(&c.Properties, "aibom:source", "image-filesystem-scan")
	addProp(&c.Properties, "aibom:path", "/"+name)
	addProp(&c.Properties, "aibom:size-bytes", fmt.Sprintf("%d", size))
	if digest != "" {
		c.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: digest}}
	}
	return c
}

// --- agent configuration files ---

func isAgentConfig(base string) bool {
	switch base {
	case "crew.yaml", "crew.yml", "agents.yaml", "agents.yml",
		"langgraph.json", "agent.yaml", "agent.yml", "autogen.json",
		"assistant.yaml", "assistant.yml":
		return true
	}
	return false
}

func agentComponent(name string) cdx.Component {
	c := cdx.Component{
		Type:   cdx.ComponentTypeApplication,
		Name:   path.Base(name),
		BOMRef: "aibom:agent:" + strings.ReplaceAll(name, "/", "_"),
	}
	addProp(&c.Properties, "aibom:category", catAgent)
	addProp(&c.Properties, "aibom:source", "image-filesystem-scan")
	addProp(&c.Properties, "aibom:path", "/"+name)
	return c
}

// --- MCP server declarations ---

func isMCPConfig(base string) bool {
	switch base {
	case ".mcp.json", "mcp.json", "claude_desktop_config.json":
		return true
	}
	return false
}

// mcpComponents parses the mcpServers map from an MCP config file and emits one
// component per declared server.
func mcpComponents(name string, data []byte) []cdx.Component {
	var doc struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
			URL     string   `json:"url"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	names := make([]string, 0, len(doc.MCPServers))
	for k := range doc.MCPServers {
		names = append(names, k)
	}
	sort.Strings(names)

	var comps []cdx.Component
	for _, srv := range names {
		s := doc.MCPServers[srv]
		c := cdx.Component{
			Type:   cdx.ComponentTypeApplication,
			Name:   srv,
			BOMRef: "aibom:mcp:" + srv,
		}
		addProp(&c.Properties, "aibom:category", catMCP)
		addProp(&c.Properties, "aibom:source", "mcp-config")
		addProp(&c.Properties, "aibom:path", "/"+name)
		if cmd := strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " ")); cmd != "" {
			addProp(&c.Properties, "aibom:mcp-command", cmd)
		}
		if s.URL != "" {
			addProp(&c.Properties, "aibom:mcp-url", s.URL)
		}
		comps = append(comps, c)
	}
	return comps
}

// ---------------------------------------------------------------------------
// Docker Model Runner artefacts
// ---------------------------------------------------------------------------

// dmrModel mirrors the JSON emitted by `docker model inspect` / `list --json`.
type dmrModel struct {
	ID      string   `json:"id"`
	Tags    []string `json:"tags"`
	Created int64    `json:"created"`
	Config  struct {
		Format       string `json:"format"`
		Quantization string `json:"quantization"`
		Parameters   string `json:"parameters"`
		Architecture string `json:"architecture"`
		Size         string `json:"size"`
	} `json:"config"`
}

func dmrInspect(model string) ([]dmrModel, error) {
	data, err := exec.Command("docker", "model", "inspect", model).Output()
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", model, err)
	}
	var m dmrModel
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("decode inspect: %w", err)
	}
	return []dmrModel{m}, nil
}

func dmrList() ([]dmrModel, error) {
	data, err := exec.Command("docker", "model", "list", "--json").Output()
	if err != nil {
		return nil, fmt.Errorf("list: %w", err)
	}
	var ms []dmrModel
	if err := json.Unmarshal(data, &ms); err != nil {
		return nil, fmt.Errorf("decode list: %w", err)
	}
	return ms, nil
}

// component turns a Docker Model Runner artefact into a CycloneDX ML model.
func (m dmrModel) component() cdx.Component {
	name, version := splitTag(m.Tags)
	c := cdx.Component{
		Type:    cdx.ComponentTypeMachineLearningModel,
		Name:    name,
		Version: version,
		BOMRef:  "aibom:" + m.ID,
	}
	if arch := m.Config.Architecture; arch != "" {
		c.ModelCard = &cdx.MLModelCard{
			ModelParameters: &cdx.MLModelParameters{
				ArchitectureFamily: arch,
				ModelArchitecture:  arch,
			},
		}
	}
	addProp(&c.Properties, "aibom:category", catModel)
	addProp(&c.Properties, "aibom:source", "docker-model-runner")
	addProp(&c.Properties, "aibom:format", m.Config.Format)
	addProp(&c.Properties, "aibom:quantization", m.Config.Quantization)
	addProp(&c.Properties, "aibom:parameters", m.Config.Parameters)
	addProp(&c.Properties, "aibom:size", m.Config.Size)
	if len(m.Tags) > 0 {
		addProp(&c.Properties, "aibom:tags", strings.Join(m.Tags, ", "))
	}
	if d := strings.TrimPrefix(m.ID, "sha256:"); d != m.ID {
		c.Hashes = &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: d}}
	}
	return c
}

// splitTag derives a name and version from OCI tags like
// "docker.io/ai/smollm2:360M-Q4_K_M".
func splitTag(tags []string) (name, version string) {
	if len(tags) == 0 {
		return "unknown-model", ""
	}
	ref := strings.TrimPrefix(tags[0], "docker.io/")
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return ref, ""
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

func addProp(props **[]cdx.Property, name, value string) {
	if value == "" {
		return
	}
	if *props == nil {
		*props = &[]cdx.Property{}
	}
	list := append(**props, cdx.Property{Name: name, Value: value})
	*props = &list
}

func digestOrPath(digest, name string) string {
	if digest != "" {
		return digest
	}
	return strings.ReplaceAll(name, "/", "_")
}

func readCapped(r io.Reader, n int64) []byte {
	data, _ := io.ReadAll(io.LimitReader(r, n))
	return data
}

func bomComponents(bom *cdx.BOM) []cdx.Component {
	if bom.Components == nil {
		return nil
	}
	return *bom.Components
}

func countCategories(comps []cdx.Component) map[string]int {
	counts := map[string]int{}
	for _, c := range comps {
		if c.Properties == nil {
			continue
		}
		for _, p := range *c.Properties {
			if p.Name == "aibom:category" {
				counts[p.Value]++
			}
		}
	}
	return counts
}

func annotate(bom *cdx.BOM, counts map[string]int) {
	if bom.Metadata == nil {
		bom.Metadata = &cdx.Metadata{}
	}
	props := []cdx.Property{{Name: "aibom:generator", Value: "aibom-scout"}}
	for _, cat := range []string{catModel, catDataset, catFramework, catAgent, catMCP} {
		if counts[cat] > 0 {
			props = append(props, cdx.Property{Name: "aibom:" + cat + "-count", Value: fmt.Sprintf("%d", counts[cat])})
		}
	}
	if bom.Metadata.Properties != nil {
		props = append(*bom.Metadata.Properties, props...)
	}
	bom.Metadata.Properties = &props
}

func writeBOM(bom *cdx.BOM, out string) {
	w := os.Stdout
	if out != "" {
		f, err := os.Create(out)
		if err != nil {
			fatalf("create %s: %v", out, err)
		}
		defer f.Close()
		w = f
	}
	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	if err := enc.Encode(bom); err != nil {
		fatalf("encode: %v", err)
	}
}

func reportCounts(counts map[string]int) {
	fmt.Fprintf(os.Stderr, "AI-BOM: %d models, %d datasets, %d frameworks, %d agents, %d MCP servers\n",
		counts[catModel], counts[catDataset], counts[catFramework], counts[catAgent], counts[catMCP])
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
