// Package sbom writes the SPDX document attested on a model image: the
// checkpoint as a package with every file's hash, and the base image.
package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/giantswarm/models/internal/modelcar"
	"github.com/giantswarm/models/internal/spec"
)

// Document is an SPDX 2.3 JSON document.
type Document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      CreationInfo   `json:"creationInfo"`
	Packages          []Package      `json:"packages"`
	Files             []File         `json:"files,omitempty"`
	Relationships     []Relationship `json:"relationships"`
}

// CreationInfo names the producer.
type CreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// Package is the checkpoint or the base image.
type Package struct {
	Name                  string        `json:"name"`
	SPDXID                string        `json:"SPDXID"`
	VersionInfo           string        `json:"versionInfo"`
	DownloadLocation      string        `json:"downloadLocation"`
	FilesAnalyzed         bool          `json:"filesAnalyzed"`
	LicenseConcluded      string        `json:"licenseConcluded"`
	LicenseDeclared       string        `json:"licenseDeclared"`
	CopyrightText         string        `json:"copyrightText"`
	PrimaryPackagePurpose string        `json:"primaryPackagePurpose,omitempty"`
	ExternalRefs          []ExternalRef `json:"externalRefs,omitempty"`
	HasFiles              []string      `json:"hasFiles,omitempty"`
}

// ExternalRef is a package URL.
type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// File is one file of the weights layer.
type File struct {
	FileName         string     `json:"fileName"`
	SPDXID           string     `json:"SPDXID"`
	Checksums        []Checksum `json:"checksums"`
	LicenseConcluded string     `json:"licenseConcluded"`
	CopyrightText    string     `json:"copyrightText"`
}

// Checksum is a file hash.
type Checksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// Relationship links elements.
type Relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

const (
	docID   = "SPDXRef-DOCUMENT"
	modelID = "SPDXRef-Package-model"
	baseID  = "SPDXRef-Package-base"
	// noAssertion is SPDX for "not stated".
	noAssertion = "NOASSERTION"
)

// Build describes the published image as an SPDX document.
func Build(m *spec.ModelImage, p *modelcar.Published, tool string, now time.Time) *Document {
	hf := m.Spec.HuggingFace
	license := m.Spec.License
	if license == "" {
		license = noAssertion
	}
	doc := &Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            docID,
		Name:              fmt.Sprintf("%s@%s", p.Reference, p.Digest),
		DocumentNamespace: fmt.Sprintf("https://github.com/giantswarm/models/spdx/%s/%s", m.Metadata.Name, p.Digest.Hex),
		CreationInfo: CreationInfo{
			Created:  now.UTC().Format(time.RFC3339),
			Creators: []string{"Tool: " + tool, "Organization: Giant Swarm"},
		},
		Relationships: []Relationship{
			{docID, "DESCRIBES", modelID},
			{docID, "DESCRIBES", baseID},
			{modelID, "DEPENDS_ON", baseID},
		},
	}
	model := Package{
		Name:                  hf.Repository,
		SPDXID:                modelID,
		VersionInfo:           hf.Revision,
		DownloadLocation:      m.HubURL(),
		FilesAnalyzed:         true,
		LicenseConcluded:      license,
		LicenseDeclared:       license,
		CopyrightText:         noAssertion,
		PrimaryPackagePurpose: "OTHER",
		ExternalRefs: []ExternalRef{{
			ReferenceCategory: "PACKAGE-MANAGER",
			ReferenceType:     "purl",
			ReferenceLocator:  fmt.Sprintf("pkg:huggingface/%s@%s", hf.Repository, hf.Revision),
		}},
	}
	for i, f := range p.Files {
		id := fmt.Sprintf("SPDXRef-File-%d", i+1)
		doc.Files = append(doc.Files, File{
			FileName:         "./" + f.Path,
			SPDXID:           id,
			Checksums:        []Checksum{{Algorithm: "SHA256", ChecksumValue: f.SHA256}},
			LicenseConcluded: noAssertion,
			CopyrightText:    noAssertion,
		})
		model.HasFiles = append(model.HasFiles, id)
		doc.Relationships = append(doc.Relationships, Relationship{modelID, "CONTAINS", id})
	}
	base := Package{
		Name:                  baseName(p.Base),
		SPDXID:                baseID,
		VersionInfo:           baseVersion(p.Base),
		DownloadLocation:      p.Base,
		FilesAnalyzed:         false,
		LicenseConcluded:      noAssertion,
		LicenseDeclared:       noAssertion,
		CopyrightText:         noAssertion,
		PrimaryPackagePurpose: "CONTAINER",
	}
	if purl := basePURL(p.Base); purl != "" {
		base.ExternalRefs = []ExternalRef{{ReferenceCategory: "PACKAGE-MANAGER", ReferenceType: "purl", ReferenceLocator: purl}}
	}
	doc.Packages = []Package{model, base}
	return doc
}

// JSON renders the document.
func (d *Document) JSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// baseName is the repository path of a pinned reference without host and digest.
func baseName(ref string) string {
	ref = strings.SplitN(ref, "@", 2)[0]
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	if i := strings.Index(ref, "/"); i >= 0 && strings.ContainsAny(ref[:i], ".:") {
		ref = ref[i+1:]
	}
	return ref
}

// baseVersion is the tag of a reference, or its digest when it carries no tag.
func baseVersion(ref string) string {
	repoTag, digest, _ := strings.Cut(ref, "@")
	if i := strings.LastIndex(repoTag, ":"); i > strings.LastIndex(repoTag, "/") {
		return repoTag[i+1:]
	}
	return digest
}

// basePURL is the pkg:oci URL of a digest-pinned reference.
func basePURL(ref string) string {
	repoTag, digest, ok := strings.Cut(ref, "@")
	if !ok {
		return ""
	}
	repo := repoTag
	tag := ""
	if i := strings.LastIndex(repoTag, ":"); i > strings.LastIndex(repoTag, "/") {
		repo, tag = repoTag[:i], repoTag[i+1:]
	}
	name := repo[strings.LastIndex(repo, "/")+1:]
	purl := fmt.Sprintf("pkg:oci/%s@%s?repository_url=%s", name, digest, repo)
	if tag != "" {
		purl += "&tag=" + tag
	}
	return purl
}
