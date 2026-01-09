/*
Package dhi provides a concrete Cataloger implementation for capturing packages embedded within
Docker Hardened Images (DHI) SPDX SBOM files found at /opt/docker/sbom/.
*/
package dhi

import (
	"context"
	"net/url"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

const catalogerName = "dhi-cataloger"

// NewCataloger returns a new DHI cataloger object loaded from saved SPDX SBOM JSON files.
func NewCataloger() pkg.Cataloger {
	return generic.NewCataloger(catalogerName).
		WithParserByGlobs(parseSPDX,
			"/opt/docker/sbom/**/*.json",
		)
}

func parseSPDX(_ context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	s, sFormat, _, err := format.Decode(reader)
	if err != nil {
		return nil, nil, err
	}

	if s == nil {
		log.WithFields("path", reader.RealPath).Trace("file is not an SBOM")
		return nil, nil, nil
	}

	// DHI uses SPDX JSON SBOMs
	if sFormat != "spdx-json" {
		log.WithFields("path", reader.RealPath).Trace("file is not an SPDX JSON SBOM")
		return nil, nil, nil
	}

	var pkgs []pkg.Package
	for _, p := range s.Artifacts.Packages.Sorted() {
		// We only want to report DHI packages (pkg:dhi/... for compiled packages)
		// Skip CONTAINER-type packages (pkg:docker/dhi/...) as those represent the image itself
		if !strings.HasPrefix(p.PURL, "pkg:dhi/") {
			continue
		}

		p.FoundBy = catalogerName
		p.Type = pkg.DHIPkg
		// replace all locations on the package with the location of the SBOM file.
		p.Locations = file.NewLocationSet(
			reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		)

		// Parse the DHI-specific metadata from the PURL
		metadata, err := parseDHIPURL(p.PURL)
		if err != nil {
			log.WithFields("purl", p.PURL, "error", err).Debug("unable to parse DHI PURL")
			continue
		}

		p.Metadata = metadata
		pkgs = append(pkgs, p)
	}

	return pkgs, filterRelationships(s.Relationships, pkgs), nil
}

func parseDHIPURL(p string) (*pkg.DHISBOMEntry, error) {
	purl, err := packageurl.FromString(p)
	if err != nil {
		return nil, err
	}

	entry := pkg.DHISBOMEntry{
		Name:    purl.Name,
		Version: purl.Version,
	}

	for _, q := range purl.Qualifiers {
		switch q.Key {
		case "platform":
			// URL decode the platform value (e.g., linux%2Farm64 -> linux/arm64)
			decoded, err := url.QueryUnescape(q.Value)
			if err != nil {
				entry.Platform = q.Value
			} else {
				entry.Platform = decoded
			}
		case "os_name":
			entry.OSName = q.Value
		case "os_version":
			entry.OSVersion = q.Value
		}
	}

	return &entry, nil
}

// filterRelationships filters out relationships that are not related to DHI packages
// and replaces the package information with the one with completed info
func filterRelationships(relationships []artifact.Relationship, pkgs []pkg.Package) []artifact.Relationship {
	var result []artifact.Relationship
	for _, r := range relationships {
		if value, ok := r.From.(pkg.Package); ok {
			found := false
			for _, p := range pkgs {
				if value.PURL == p.PURL {
					r.From = p
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		if value, ok := r.To.(pkg.Package); ok {
			found := false
			for _, p := range pkgs {
				if value.PURL == p.PURL {
					r.To = p
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}
		result = append(result, r)
	}

	return result
}
