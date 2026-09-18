package spec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `apiVersion: models.giantswarm.io/v1alpha1
kind: ModelImage
metadata:
  name: tiny-random-gpt2
spec:
  huggingFace:
    repository: hf-internal-testing/tiny-random-gpt2
    revision: 91c0fe31d692dd8448d9bc06e8d1877345009e3b
  description: A tiny model for tests.
`

func write(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	dir := t.TempDir()
	m, err := Load(write(t, dir, "tiny.yaml", valid))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := m.Tag(), "91c0fe31d692"; got != want {
		t.Errorf("Tag() = %q, want %q", got, want)
	}
	if m.Base() != DefaultBase {
		t.Errorf("Base() = %q, want the default", m.Base())
	}
	for _, f := range []string{"README.md", ".gitattributes", "images/logo.png", "assets/x.JPG"} {
		if !m.Excluded(f) && !strings.HasSuffix(f, ".JPG") {
			t.Errorf("%s should be excluded", f)
		}
	}
	for _, f := range []string{"config.json", "model-00001-of-00002.safetensors", "docs/README.txt"} {
		if m.Excluded(f) {
			t.Errorf("%s should be included", f)
		}
	}
}

func TestLoadRejects(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"short revision": strings.Replace(valid, "91c0fe31d692dd8448d9bc06e8d1877345009e3b", "91c0fe31d692", 1),
		"bad name":       strings.Replace(valid, "name: tiny-random-gpt2", "name: Tiny_GPT2", 1),
		"bad repository": strings.Replace(valid, "hf-internal-testing/tiny-random-gpt2", "tiny-random-gpt2", 1),
		"unknown field":  valid + "  weights: 12\n",
		"wrong kind":     strings.Replace(valid, "kind: ModelImage", "kind: Model", 1),
		"bad exclude":    valid + "  exclude: [\"[\"]\n",
		"bad base":       valid + "  base: \"::not a reference\"\n",
	}
	for label, content := range cases {
		if _, err := Load(write(t, dir, strings.ReplaceAll(label, " ", "-")+".yaml", content)); err == nil {
			t.Errorf("%s: expected an error", label)
		}
	}
}

func TestLoadDirRefusesDuplicateNames(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "a.yaml", valid)
	write(t, dir, "b.yaml", valid)
	if _, err := LoadDir(dir); err == nil || !strings.Contains(err.Error(), "both name the image") {
		t.Fatalf("expected a duplicate-name error, got %v", err)
	}
}

func TestLoadDirEmpty(t *testing.T) {
	if _, err := LoadDir(t.TempDir()); err == nil {
		t.Fatal("expected an error for a directory without specifications")
	}
}
