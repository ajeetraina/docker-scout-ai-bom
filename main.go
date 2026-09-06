// Command aibom-scout discovers the AI composition of a container image or of
// the models managed by Docker Model Runner, and emits it as a CycloneDX AI-BOM.
//
// This is about COMPOSITION, not vulnerabilities: an AI-BOM answers "what AI is
// in here?" - models, frameworks, agents, and MCP servers - for inventory,
// provenance, licensing, and governance. It is not a CVE scanner.
//
// Three modes:
//
//	aibom-scout image  <image[:tag]>  # AI composition of a container image
//	aibom-scout model  [model]        # Docker Model Runner artefact(s)
//	aibom-scout source [dir]          # AI called by source code in a repo
//
// The image mode uses `docker scout sbom` as the software baseline, then
// discovers AI components the SBOM misses:
//
//   - models    - weight files baked into the image (.gguf, .safetensors, …)
//   - datasets  - dataset files (.parquet, .arrow, …)
//   - frameworks - AI libraries among the SBOM packages (torch, langchain, …)
//   - agents    - agent configuration files (crew.yaml, langgraph.json, …)
//   - mcp       - MCP servers declared in config files (.mcp.json, …)
//   - providers - hosted inference providers signalled by env vars (OpenAI, …)
//   - prompts   - system prompts and prompt templates (system_prompt.txt, …)
//
// The model mode inspects Docker Model Runner artefacts (`docker model
// inspect` / `list --json`) - GGUF models distributed as OCI artefacts, not
// container images.
//
// The source mode scans a directory tree for AI SDK imports (OpenAI, Anthropic,
// LangChain, …) and referenced model identifiers, capturing the AI a codebase
// calls even when nothing is registered.
package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
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
	catProvider  = "inference-provider"
	catPrompt    = "prompt"
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
	case "source":
		runSource(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  aibom-scout image  <image[:tag]> [-o out.cdx.json]")
	fmt.Fprintln(os.Stderr, "  aibom-scout model  [model]       [-o out.cdx.json]")
	fmt.Fprintln(os.Stderr, "  aibom-scout source [dir]         [-o out.cdx.json]")
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

	// Detect hosted inference providers from the image's declared env vars.
	providers, err := detectProviders(image)
	if err != nil {
		fatalf("inspect image env: %v", err)
	}
	comps = append(comps, providers...)
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

// runSource discovers the AI called by source code in a directory tree.
func runSource(argv []string) {
	fset := flag.NewFlagSet("source", flag.ExitOnError)
	out := fset.String("o", "", "write AI-BOM here (default: stdout)")
	fset.Parse(argv)
	root := "."
	if fset.NArg() == 1 {
		root = fset.Arg(0)
	}

	comps, err := scanSource(root)
	if err != nil {
		fatalf("scan source: %v", err)
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
		nameLower := strings.ToLower(hdr.Name)
		base := path.Base(nameLower)
		switch {
		case isMCPConfig(base):
			data := readCapped(tr, 1<<20)
			comps = append(comps, mcpComponents(hdr.Name, data)...)
		case isAgentConfig(base):
			comps = append(comps, agentComponent(hdr.Name))
		case isPromptFile(nameLower, base):
			comps = append(comps, promptComponent(hdr.Name, hdr.Size))
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

// --- system prompts / prompt templates ---

// promptExts are template/prompt file extensions treated as prompt artefacts,
// both on their own and inside a prompts/ directory.
var promptExts = map[string]bool{
	".prompt": true, ".jinja": true, ".j2": true, ".tmpl": true,
}

// promptDirExts are text extensions counted as prompts only when they live
// under a prompts/ directory (keeps the heuristic high-signal).
var promptDirExts = map[string]bool{
	".txt": true, ".md": true, ".yaml": true, ".yml": true, ".json": true,
}

// isPromptFile reports whether a path looks like a system prompt or prompt
// template. name is the lowercased full path, base its lowercased basename.
func isPromptFile(name, base string) bool {
	ext := path.Ext(base)
	switch {
	case promptExts[ext]:
		return true
	case strings.HasPrefix(base, "system_prompt") || strings.HasPrefix(base, "system-prompt"):
		return true
	case base == "system.prompt" || base == "prompt.txt" || base == "prompt_template.txt",
		base == "prompts.yaml" || base == "prompts.yml" || base == "prompts.json":
		return true
	case strings.Contains(name, "/prompts/") && promptDirExts[ext]:
		return true
	}
	return false
}

func promptComponent(name string, size int64) cdx.Component {
	c := cdx.Component{
		Type:   cdx.ComponentTypeData,
		Name:   path.Base(name),
		BOMRef: "aibom:prompt:" + strings.ReplaceAll(name, "/", "_"),
	}
	addProp(&c.Properties, "aibom:category", catPrompt)
	addProp(&c.Properties, "aibom:source", "image-filesystem-scan")
	addProp(&c.Properties, "aibom:path", "/"+name)
	addProp(&c.Properties, "aibom:size-bytes", fmt.Sprintf("%d", size))
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
// Hosted inference providers (remote models called by the image)
// ---------------------------------------------------------------------------

// providerEnv maps an environment variable name to the hosted inference
// provider it signals. The variable's *value* (often a secret) is never read
// or emitted - only its presence matters.
var providerEnv = map[string]string{
	"OPENAI_API_KEY": "OpenAI", "OPENAI_API_BASE": "OpenAI", "OPENAI_BASE_URL": "OpenAI",
	"AZURE_OPENAI_API_KEY": "Azure OpenAI", "AZURE_OPENAI_ENDPOINT": "Azure OpenAI",
	"ANTHROPIC_API_KEY": "Anthropic",
	"CO_API_KEY":        "Cohere", "COHERE_API_KEY": "Cohere",
	"GOOGLE_API_KEY": "Google Gemini", "GEMINI_API_KEY": "Google Gemini",
	"MISTRAL_API_KEY":          "Mistral",
	"GROQ_API_KEY":             "Groq",
	"TOGETHER_API_KEY":         "Together AI",
	"FIREWORKS_API_KEY":        "Fireworks AI",
	"REPLICATE_API_TOKEN":      "Replicate",
	"HUGGINGFACEHUB_API_TOKEN": "Hugging Face", "HF_TOKEN": "Hugging Face",
	"PERPLEXITY_API_KEY": "Perplexity",
	"DEEPSEEK_API_KEY":   "DeepSeek",
	"XAI_API_KEY":        "xAI",
	"DASHSCOPE_API_KEY":  "Alibaba DashScope",
	"OLLAMA_HOST":        "Ollama",
}

// endpointEnv names env vars whose value is a (non-secret) endpoint URL worth
// recording against the provider.
var endpointEnv = map[string]bool{
	"OPENAI_API_BASE": true, "OPENAI_BASE_URL": true,
	"AZURE_OPENAI_ENDPOINT": true, "OLLAMA_HOST": true,
}

// detectProviders inspects the image's declared env vars and emits one
// component per hosted inference provider it finds.
func detectProviders(image string) ([]cdx.Component, error) {
	env, err := imageEnv(image)
	if err != nil {
		return nil, err
	}
	type acc struct {
		keys     []string
		endpoint string
	}
	found := map[string]*acc{}
	for _, kv := range env {
		key, val, _ := strings.Cut(kv, "=")
		provider, ok := providerEnv[key]
		if !ok {
			continue
		}
		a := found[provider]
		if a == nil {
			a = &acc{}
			found[provider] = a
		}
		a.keys = append(a.keys, key)
		if endpointEnv[key] && val != "" {
			a.endpoint = val
		}
	}

	providers := make([]string, 0, len(found))
	for p := range found {
		providers = append(providers, p)
	}
	sort.Strings(providers)

	var comps []cdx.Component
	for _, p := range providers {
		a := found[p]
		sort.Strings(a.keys)
		c := cdx.Component{
			Type:   cdx.ComponentTypeApplication,
			Name:   p,
			BOMRef: "aibom:provider:" + strings.ToLower(strings.ReplaceAll(p, " ", "-")),
		}
		addProp(&c.Properties, "aibom:category", catProvider)
		addProp(&c.Properties, "aibom:source", "image-env")
		addProp(&c.Properties, "aibom:env", strings.Join(a.keys, ", "))
		addProp(&c.Properties, "aibom:endpoint", a.endpoint)
		comps = append(comps, c)
	}
	return comps, nil
}

// imageEnv returns the image's declared environment variables (KEY=VALUE).
func imageEnv(image string) ([]string, error) {
	out, err := exec.Command("docker", "image", "inspect", "--format", "{{json .Config.Env}}", image).Output()
	if err != nil {
		return nil, err
	}
	var env []string
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, fmt.Errorf("decode env: %w", err)
	}
	return env, nil
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
// Source code scan (AI called by your code)
// ---------------------------------------------------------------------------

// modRule maps an imported module to an AI-BOM category and display name. When
// prefix is true it also matches submodules (token., token/, token-).
type modRule struct {
	prefix bool
	token  string
	cat    string
	name   string
}

// moduleRules are evaluated in order; the first match wins.
var moduleRules = []modRule{
	{true, "google.generativeai", catProvider, "Google Gemini"},
	{true, "google.genai", catProvider, "Google Gemini"},
	{false, "@google/generative-ai", catProvider, "Google Gemini"},
	{true, "@google/genai", catProvider, "Google Gemini"},
	{true, "@ai-sdk/openai", catProvider, "OpenAI"},
	{true, "@ai-sdk/anthropic", catProvider, "Anthropic"},
	{true, "openai", catProvider, "OpenAI"},
	{true, "anthropic", catProvider, "Anthropic"},
	{true, "@anthropic-ai", catProvider, "Anthropic"},
	{true, "cohere", catProvider, "Cohere"},
	{true, "mistralai", catProvider, "Mistral"},
	{true, "groq", catProvider, "Groq"},
	{true, "ollama", catProvider, "Ollama"},
	{true, "langchain", catFramework, "LangChain"},
	{true, "@langchain", catFramework, "LangChain"},
	{true, "langgraph", catFramework, "LangGraph"},
	{true, "llama_index", catFramework, "LlamaIndex"},
	{false, "llamaindex", catFramework, "LlamaIndex"},
	{true, "crewai", catFramework, "CrewAI"},
	{true, "autogen", catFramework, "AutoGen"},
	{true, "pyautogen", catFramework, "AutoGen"},
	{true, "transformers", catFramework, "Transformers"},
	{true, "torch", catFramework, "PyTorch"},
	{true, "tensorflow", catFramework, "TensorFlow"},
	{true, "dspy", catFramework, "DSPy"},
	{true, "haystack", catFramework, "Haystack"},
	{true, "semantic_kernel", catFramework, "Semantic Kernel"},
	{true, "smolagents", catFramework, "smolagents"},
	{true, "litellm", catFramework, "LiteLLM"},
	{true, "guidance", catFramework, "Guidance"},
	{true, "@modelcontextprotocol", catFramework, "MCP"},
	{false, "mcp", catFramework, "MCP"},
	{true, "ai", catFramework, "Vercel AI SDK"},
}

func matchModule(mod string) (cat, name string, ok bool) {
	mod = strings.ToLower(strings.Trim(mod, `'" `))
	for _, r := range moduleRules {
		if r.prefix {
			if mod == r.token ||
				strings.HasPrefix(mod, r.token+".") ||
				strings.HasPrefix(mod, r.token+"/") ||
				strings.HasPrefix(mod, r.token+"-") {
				return r.cat, r.name, true
			}
		} else if mod == r.token {
			return r.cat, r.name, true
		}
	}
	return "", "", false
}

// modelPrefixes identify known model identifiers referenced in code.
var modelPrefixes = []string{
	"gpt-", "gpt4", "o1", "o1-", "o3", "o3-", "o4", "chatgpt", "text-embedding-",
	"dall-e", "whisper-", "claude-", "gemini-", "gemma", "mistral-", "mixtral",
	"codestral", "llama-", "llama3", "llama2", "qwen", "deepseek", "phi-", "phi3",
	"command-", "command_", "embed-", "nomic-embed", "mxbai-embed",
}

func isKnownModel(v string) bool {
	v = strings.ToLower(v)
	for _, p := range modelPrefixes {
		if strings.HasPrefix(v, p) {
			return true
		}
	}
	return false
}

var (
	pyImport   = regexp.MustCompile(`(?m)^\s*(?:from|import)\s+([a-zA-Z0-9_.]+)`)
	jsFrom     = regexp.MustCompile(`from\s+['"]([^'"]+)['"]`)
	jsRequire  = regexp.MustCompile(`require\(\s*['"]([^'"]+)['"]\s*\)`)
	jsBare     = regexp.MustCompile(`import\s+['"]([^'"]+)['"]`)
	modelRef   = regexp.MustCompile(`(?i)\bmodel["']?\s*[=:]\s*["']([^"']+)["']`)
	skipDirSet = map[string]bool{
		"node_modules": true, ".git": true, "vendor": true, "dist": true,
		"build": true, ".venv": true, "venv": true, "__pycache__": true,
		".next": true, "target": true, ".idea": true, "site-packages": true,
		".mypy_cache": true, ".pytest_cache": true,
	}
)

func langOf(p string) string {
	switch strings.ToLower(filepath.Ext(p)) {
	case ".py":
		return "py"
	case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
		return "js"
	}
	return ""
}

// scanSource walks a directory tree and discovers AI providers, frameworks, and
// referenced models from import statements and model identifiers in the code.
func scanSource(root string) ([]cdx.Component, error) {
	type key struct{ cat, name string }
	found := map[key]map[string]bool{}
	add := func(cat, name, file string) {
		k := key{cat, name}
		if found[k] == nil {
			found[k] = map[string]bool{}
		}
		found[k][file] = true
	}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirSet[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		lang := langOf(p)
		if lang == "" {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Size() > 4<<20 {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		content := string(data)
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			rel = p
		}

		if lang == "py" {
			for _, m := range pyImport.FindAllStringSubmatch(content, -1) {
				if cat, name, ok := matchModule(m[1]); ok {
					add(cat, name, rel)
				}
			}
		} else {
			for _, re := range []*regexp.Regexp{jsFrom, jsRequire, jsBare} {
				for _, m := range re.FindAllStringSubmatch(content, -1) {
					if cat, name, ok := matchModule(m[1]); ok {
						add(cat, name, rel)
					}
				}
			}
		}
		for _, m := range modelRef.FindAllStringSubmatch(content, -1) {
			if isKnownModel(m[1]) {
				add(catModel, m[1], rel)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	keys := make([]key, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].cat != keys[j].cat {
			return keys[i].cat < keys[j].cat
		}
		return keys[i].name < keys[j].name
	})

	comps := make([]cdx.Component, 0, len(keys))
	for _, k := range keys {
		files := make([]string, 0, len(found[k]))
		for f := range found[k] {
			files = append(files, f)
		}
		sort.Strings(files)
		comps = append(comps, sourceComponent(k.cat, k.name, files))
	}
	return comps, nil
}

func sourceComponent(cat, name string, files []string) cdx.Component {
	ctype := cdx.ComponentTypeApplication
	if cat == catModel {
		ctype = cdx.ComponentTypeMachineLearningModel
	}
	c := cdx.Component{
		Type:   ctype,
		Name:   name,
		BOMRef: "aibom:src:" + cat + ":" + slug(name),
	}
	addProp(&c.Properties, "aibom:category", cat)
	addProp(&c.Properties, "aibom:source", "source-code-scan")
	addProp(&c.Properties, "aibom:reference-count", fmt.Sprintf("%d", len(files)))
	shown := files
	if len(shown) > 10 {
		shown = shown[:10]
	}
	usedIn := strings.Join(shown, ", ")
	if len(files) > len(shown) {
		usedIn += fmt.Sprintf(", (+%d more)", len(files)-len(shown))
	}
	addProp(&c.Properties, "aibom:used-in", usedIn)
	return c
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	return b.String()
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
	for _, cat := range []string{catModel, catDataset, catFramework, catAgent, catMCP, catProvider, catPrompt} {
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
	fmt.Fprintf(os.Stderr, "AI-BOM: %d models, %d datasets, %d frameworks, %d agents, %d MCP servers, %d providers, %d prompts\n",
		counts[catModel], counts[catDataset], counts[catFramework], counts[catAgent], counts[catMCP], counts[catProvider], counts[catPrompt])
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
	os.Exit(1)
}
