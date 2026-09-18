// Package spec reads the model image specifications under models/: one file
// per curated model, naming the Hugging Face repository and the revision the
// image is built from.
package spec

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"sigs.k8s.io/yaml"
)

const (
	// APIVersion and Kind identify a specification file.
	APIVersion = "models.giantswarm.io/v1alpha1"
	Kind       = "ModelImage"

	// DefaultBase is the image the weights layer is appended to: a shell with
	// ln, ls and sleep for KServe's modelcar sidecar, nothing else.
	// renovate: datasource=docker depName=gsoci.azurecr.io/giantswarm/busybox
	DefaultBase = "gsoci.azurecr.io/giantswarm/busybox:1.38.0"

	// TagLength is how many characters of the revision make the image tag.
	TagLength = 12

	// MountPath is where the weights live in the image (KServe's modelcar
	// contract: the runtime reads them at /mnt/models -> /proc/<pid>/root/models).
	MountPath = "models"
)

// DefaultExclude lists the repository files that are not weights, tokenizer or
// configuration and stay out of the image: the model card and its images.
var DefaultExclude = []string{"README.md", ".gitattributes", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.svg", "*.webp"}

var (
	nameRE       = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	repositoryRE = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	revisionRE   = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// ModelImage is one specification file.
type ModelImage struct {
	APIVersion string   `json:"apiVersion"`
	Kind       string   `json:"kind"`
	Metadata   Metadata `json:"metadata"`
	Spec       Spec     `json:"spec"`

	// Path is the file the specification was read from.
	Path string `json:"-"`
}

// Metadata names the image: metadata.name is the last path element of the
// image repository and the preset name the platform charts use.
type Metadata struct {
	Name string `json:"name"`
}

// Spec is the body of a specification.
type Spec struct {
	// HuggingFace names the checkpoint.
	HuggingFace HuggingFace `json:"huggingFace"`
	// Description is a sentence about the model for the image annotations.
	Description string `json:"description,omitempty"`
	// License is the checkpoint's licence identifier (SPDX where one exists),
	// recorded in the image annotations and the SBOM.
	License string `json:"license,omitempty"`
	// Base overrides DefaultBase.
	Base string `json:"base,omitempty"`
	// Exclude replaces DefaultExclude: glob patterns matched against each
	// repository file's path and base name.
	Exclude []string `json:"exclude,omitempty"`
}

// HuggingFace is a checkpoint: a repository on the Hub and the commit to package.
type HuggingFace struct {
	Repository string `json:"repository"`
	// Revision is the full commit hash. Renovate follows the repository's
	// default branch and opens the bump.
	Revision string `json:"revision"`
}

// Load reads and validates one specification file.
func Load(file string) (*ModelImage, error) {
	raw, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	var m ModelImage
	if err := yaml.UnmarshalStrict(raw, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	m.Path = file
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return &m, nil
}

// LoadDir reads every *.yaml under dir, sorted by file name, and refuses two
// files naming the same image.
func LoadDir(dir string) ([]*ModelImage, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no specification files (*.yaml) under %s", dir)
	}
	seen := map[string]string{}
	var out []*ModelImage
	for _, f := range files {
		m, err := Load(f)
		if err != nil {
			return nil, err
		}
		if other, dup := seen[m.Metadata.Name]; dup {
			return nil, fmt.Errorf("%s and %s both name the image %q", other, f, m.Metadata.Name)
		}
		seen[m.Metadata.Name] = f
		out = append(out, m)
	}
	return out, nil
}

// Validate checks the fields a build depends on.
func (m *ModelImage) Validate() error {
	var problems []string
	if m.APIVersion != APIVersion {
		problems = append(problems, fmt.Sprintf("apiVersion must be %s, got %q", APIVersion, m.APIVersion))
	}
	if m.Kind != Kind {
		problems = append(problems, fmt.Sprintf("kind must be %s, got %q", Kind, m.Kind))
	}
	if !nameRE.MatchString(m.Metadata.Name) {
		problems = append(problems, fmt.Sprintf("metadata.name %q must be lower-case letters, digits and dashes", m.Metadata.Name))
	}
	if !repositoryRE.MatchString(m.Spec.HuggingFace.Repository) {
		problems = append(problems, fmt.Sprintf("spec.huggingFace.repository %q must be <owner>/<name>", m.Spec.HuggingFace.Repository))
	}
	if !revisionRE.MatchString(m.Spec.HuggingFace.Revision) {
		problems = append(problems, fmt.Sprintf("spec.huggingFace.revision %q must be the full 40-character commit hash", m.Spec.HuggingFace.Revision))
	}
	if _, err := name.ParseReference(m.Base()); err != nil {
		problems = append(problems, fmt.Sprintf("spec.base: %v", err))
	}
	for _, pattern := range m.Excludes() {
		if _, err := path.Match(pattern, ""); err != nil {
			problems = append(problems, fmt.Sprintf("spec.exclude %q: %v", pattern, err))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid specification:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// Tag is the image tag: the first TagLength characters of the revision.
func (m *ModelImage) Tag() string {
	return m.Spec.HuggingFace.Revision[:TagLength]
}

// Base is the base image reference.
func (m *ModelImage) Base() string {
	if m.Spec.Base != "" {
		return m.Spec.Base
	}
	return DefaultBase
}

// Excludes are the patterns in force.
func (m *ModelImage) Excludes() []string {
	if m.Spec.Exclude != nil {
		return m.Spec.Exclude
	}
	return DefaultExclude
}

// Excluded reports whether a repository file stays out of the image.
func (m *ModelImage) Excluded(file string) bool {
	for _, pattern := range m.Excludes() {
		if ok, _ := path.Match(pattern, file); ok {
			return true
		}
		if ok, _ := path.Match(pattern, path.Base(file)); ok {
			return true
		}
	}
	return false
}

// HubURL is the checkpoint's page on the Hub at the pinned revision.
func (m *ModelImage) HubURL() string {
	return fmt.Sprintf("https://huggingface.co/%s/tree/%s", m.Spec.HuggingFace.Repository, m.Spec.HuggingFace.Revision)
}
