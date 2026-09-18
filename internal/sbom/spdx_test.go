package sbom

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/giantswarm/models/internal/modelcar"
	"github.com/giantswarm/models/internal/spec"
)

func TestBuild(t *testing.T) {
	m := &spec.ModelImage{Metadata: spec.Metadata{Name: "tiny"}, Spec: spec.Spec{
		HuggingFace: spec.HuggingFace{Repository: "acme/tiny", Revision: strings.Repeat("a", 40)},
	}}
	tag, _ := name.NewTag("gsoci.azurecr.io/giantswarm/models/tiny:aaaaaaaaaaaa")
	p := &modelcar.Published{
		Reference: tag,
		Digest:    v1.Hash{Algorithm: "sha256", Hex: strings.Repeat("1", 64)},
		Files: []modelcar.FileDigest{
			{Path: "models/config.json", Size: 3, SHA256: strings.Repeat("2", 64)},
			{Path: "models/model.safetensors", Size: 30, SHA256: strings.Repeat("3", 64)},
		},
		Base: "gsoci.azurecr.io/giantswarm/busybox:1.38.0@sha256:" + strings.Repeat("4", 64),
	}
	doc := Build(m, p, "models v1", time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC))
	raw, err := doc.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back["spdxVersion"] != "SPDX-2.3" || len(doc.Files) != 2 || len(doc.Packages) != 2 {
		t.Errorf("document: %s", raw)
	}
	if doc.Packages[0].LicenseDeclared != "NOASSERTION" || doc.Packages[0].ExternalRefs[0].ReferenceLocator != "pkg:huggingface/acme/tiny@"+strings.Repeat("a", 40) {
		t.Errorf("model package: %+v", doc.Packages[0])
	}
	base := doc.Packages[1]
	if base.Name != "giantswarm/busybox" || base.VersionInfo != "1.38.0" || !strings.HasPrefix(base.ExternalRefs[0].ReferenceLocator, "pkg:oci/busybox@sha256:4444") || !strings.HasSuffix(base.ExternalRefs[0].ReferenceLocator, "&tag=1.38.0") {
		t.Errorf("base package: %+v", base)
	}
	if len(doc.Relationships) != 5 || doc.Relationships[3].RelationshipType != "CONTAINS" {
		t.Errorf("relationships: %+v", doc.Relationships)
	}
}
