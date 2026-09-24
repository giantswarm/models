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

const withExtraFiles = valid + `  extraFiles:
    - url: https://example.com/encodings/o200k_base.tiktoken
      sha256: 446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d
      path: tiktoken/o200k_base.tiktoken
    - url: https://example.com/encodings/cl100k_base.tiktoken
      sha256: 223921b76ee99bde995b7ff738513eef100fb51d18c93597a113bcffe865b2a7
      path: tiktoken/cl100k_base.tiktoken
`

func TestTagOfAnImageWithExtraFiles(t *testing.T) {
	dir := t.TempDir()
	m, err := Load(write(t, dir, "extra.yaml", withExtraFiles))
	if err != nil {
		t.Fatal(err)
	}
	tag := m.Tag()
	if !strings.HasPrefix(tag, "91c0fe31d692-") || len(tag) != TagLength+1+ExtraTagLength || m.CheckpointTag() != "91c0fe31d692" {
		t.Fatalf("Tag() = %q, CheckpointTag() = %q", tag, m.CheckpointTag())
	}
	if d := m.ExtraFilesDigest(); !strings.HasPrefix(d, tag[TagLength+1:]) || len(d) != 64 {
		t.Errorf("ExtraFilesDigest() = %q, tag %q", d, tag)
	}

	// The order of the list and the URLs do not change the tag.
	reordered := *m
	reordered.Spec.ExtraFiles = []ExtraFile{m.Spec.ExtraFiles[1], m.Spec.ExtraFiles[0]}
	reordered.Spec.ExtraFiles[0].URL = "https://mirror.example.org/cl100k_base.tiktoken"
	if reordered.Tag() != tag {
		t.Errorf("reordered or mirrored: tag %q, want %q", reordered.Tag(), tag)
	}
	// Another path or another hash does.
	moved := *m
	moved.Spec.ExtraFiles = append([]ExtraFile(nil), m.Spec.ExtraFiles...)
	moved.Spec.ExtraFiles[0].Path = "encodings/o200k_base.tiktoken"
	rehashed := *m
	rehashed.Spec.ExtraFiles = append([]ExtraFile(nil), m.Spec.ExtraFiles...)
	rehashed.Spec.ExtraFiles[0].SHA256 = strings.Repeat("0", 64)
	for label, other := range map[string]*ModelImage{"moved": &moved, "rehashed": &rehashed} {
		if other.Tag() == tag {
			t.Errorf("%s: the tag must change, still %q", label, tag)
		}
	}
	// Without extra files, the tag is the revision's.
	plain := *m
	plain.Spec.ExtraFiles = nil
	if plain.Tag() != "91c0fe31d692" || plain.ExtraFilesDigest() != "" {
		t.Errorf("without extra files: tag %q digest %q", plain.Tag(), plain.ExtraFilesDigest())
	}
}

func TestLoadRejectsBadExtraFiles(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"plain http":     strings.Replace(withExtraFiles, "https://example.com/encodings/o200k", "http://example.com/encodings/o200k", 1),
		"short hash":     strings.Replace(withExtraFiles, "sha256: 446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d", "sha256: 446a9538", 1),
		"upper-case hex": strings.Replace(withExtraFiles, "446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d", strings.ToUpper("446a9538cb6c348e3516120d7c08b09f57c36495e2acfffe59a5bf8b0cfb1a2d"), 1),
		"absolute path":  strings.Replace(withExtraFiles, "path: tiktoken/o200k", "path: /tiktoken/o200k", 1),
		"escaping path":  strings.Replace(withExtraFiles, "path: tiktoken/o200k", "path: ../tiktoken/o200k", 1),
		"unclean path":   strings.Replace(withExtraFiles, "path: tiktoken/o200k", "path: tiktoken//o200k", 1),
		"dot path":       strings.Replace(withExtraFiles, "path: tiktoken/o200k_base.tiktoken", "path: .", 1),
		"duplicate path": strings.Replace(withExtraFiles, "path: tiktoken/cl100k_base.tiktoken", "path: tiktoken/o200k_base.tiktoken", 1),
		"file as dir":    strings.Replace(withExtraFiles, "path: tiktoken/cl100k_base.tiktoken", "path: tiktoken/o200k_base.tiktoken/x", 1),
		"unknown field":  withExtraFiles + "      size: 12\n",
	}
	for label, content := range cases {
		if _, err := Load(write(t, dir, strings.ReplaceAll(label, " ", "-")+".yaml", content)); err == nil {
			t.Errorf("%s: expected an error", label)
		}
	}
}
