package dhi

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestDHICataloger(t *testing.T) {
	pythonPkg := pkg.Package{
		Name:      "python",
		Version:   "3.14.2",
		Type:      pkg.DHIPkg,
		Locations: file.NewLocationSet(file.NewLocation("opt/docker/sbom/python/.spdx.python.json")),
		FoundBy:   catalogerName,
		PURL:      "pkg:dhi/python@3.14.2",
		Metadata: &pkg.DHISBOMEntry{
			Name:    "python",
			Version: "3.14.2",
		},
	}

	tests := []struct {
		name              string
		fixture           string
		wantPkgs          []pkg.Package
		wantRelationships []artifact.Relationship
		wantErr           require.ErrorAssertionFunc
	}{
		{
			name:              "parse valid Python DHI SBOM",
			fixture:           "test-fixtures/python-image",
			wantPkgs:          []pkg.Package{pythonPkg},
			wantRelationships: nil,
			wantErr:           require.NoError,
		},
		{
			name:              "skip CONTAINER packages (pkg:docker/dhi/...)",
			fixture:           "test-fixtures/container-image",
			wantPkgs:          nil,
			wantRelationships: nil,
			wantErr:           require.NoError,
		},
		{
			name:              "invalid SBOM",
			fixture:           "test-fixtures/invalid",
			wantPkgs:          nil,
			wantRelationships: nil,
			wantErr:           require.NoError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, tt.fixture).
				Expects(tt.wantPkgs, tt.wantRelationships).
				WithErrorAssertion(tt.wantErr).
				TestCataloger(t, NewCataloger())
		})
	}
}
