package packages

import (
	"fmt"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/distro"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// JsonDocument represents the syft cataloging findings as a JSON document
type JsonDocument struct {
	Artifacts             []JsonPackage      `json:"artifacts"`  // Artifacts is the list of packages discovered and placed into the catalog
	Source                JsonSource         `json:"source"`     // Source represents the original object that was cataloged
	Distro                JsonDistribution   `json:"distro"`     // Distro represents the Linux distribution that was detected from the source
	Descriptor            JsonDescriptor     `json:"descriptor"` // Descriptor is a block containing self-describing information about syft
	Schema                JsonSchema         `json:"schema"`     // Schema is a block reserved for defining the version for the shape of this JSON document and where to find the schema document to validate the shape
	ArtifactRelationships []JsonRelationship `json:"artifactRelationships"`
}

// NewJsonDocument creates and populates a new JSON document struct from the given cataloging results.
func NewJsonDocument(catalog *pkg.Catalog, srcMetadata source.Metadata, d *distro.Distro, scope source.Scope) (JsonDocument, error) {
	src, err := NewJsonSource(srcMetadata, scope)
	if err != nil {
		return JsonDocument{}, nil
	}

	doc := JsonDocument{
		Artifacts: make([]JsonPackage, 0),
		Source:    src,
		Distro:    NewJsonDistribution(d),
		Descriptor: JsonDescriptor{
			Name:    internal.ApplicationName,
			Version: version.FromBuild().Version,
		},
		Schema: JsonSchema{
			Version: internal.JSONSchemaVersion,
			URL:     fmt.Sprintf("https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-%s.json", internal.JSONSchemaVersion),
		},
		ArtifactRelationships: newJsonRelationships(pkg.NewRelationships(catalog)),
	}

	for _, p := range catalog.Sorted() {
		art, err := NewJsonPackage(p)
		if err != nil {
			return JsonDocument{}, err
		}
		doc.Artifacts = append(doc.Artifacts, art)
	}

	return doc, nil
}

// JsonDescriptor describes what created the document as well as surrounding metadata
type JsonDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type JsonSchema struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}
