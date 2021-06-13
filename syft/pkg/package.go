/*
Package pkg provides the data structures for a package, a package catalog, package types, and domain-specific metadata.
*/
package pkg

import (
	"fmt"

	"github.com/mitchellh/hashstructure/v2"

	"github.com/anchore/syft/syft/source"
)

// Package represents an application or library that has been bundled into a distributable format.
type Package struct {
	ID      ID     `hash:"ignore"` // uniquely identifies a package, set by the cataloger
	Name    string // the package name
	Version string // the version of the package
	// TODO: should FoundBy be a slice (support merging)
	FoundBy   string            // the specific cataloger that discovered this package
	Locations []source.Location `hash:"ignore"` // the locations that lead to the discovery of this package (note: this is not necessarily the locations that make up this package)
	// TODO: should we move licenses into metadata?
	Licenses     []string     // licenses discovered with the package metadata
	Language     Language     // the language ecosystem this package belongs to (e.g. JavaScript, Python, etc)
	Type         Type         // the package type (e.g. Npm, Yarn, Python, Rpm, Deb, etc)
	CPEs         []CPE        // all possible Common Platform Enumerators
	PURL         string       // the Package URL (see https://github.com/package-url/purl-spec)
	MetadataType MetadataType // the shape of the additional data in the "metadata" field
	Metadata     interface{}  // additional data found while parsing the package source
}

// Stringer to represent a package.
func (p Package) String() string {
	return fmt.Sprintf("Pkg(type=%s, name=%s, version=%s)", p.Type, p.Name, p.Version)
}

func (p Package) Fingerprint() uint64 {
	f, err := hashstructure.Hash(p, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return 0
	}
	return f
}

func (p *Package) Merge(other Package) {
	// we need to merge all fields which are ignored during fingerprinting. ID should be ignored, the original package ID
	// is used (from p). This leaves only Locations, which should be merged and sorted.
	locations := source.NewLocationSet(p.Locations...)
	for _, l := range other.Locations {
		locations.Add(l)
	}
	p.Locations = locations.ToSlice()
}
