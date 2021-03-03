package packages

import "github.com/anchore/syft/syft/distro"

// JsonDistribution provides information about a detected Linux JsonDistribution.
type JsonDistribution struct {
	Name    string `json:"name"`    // Name of the Linux distribution
	Version string `json:"version"` // Version of the Linux distribution (major or major.minor version)
	IDLike  string `json:"idLike"`  // the ID_LIKE field found within the /etc/os-release file
}

// NewJsonDistribution creates a struct with the Linux distribution to be represented in JSON.
func NewJsonDistribution(d *distro.Distro) JsonDistribution {
	if d == nil {
		return JsonDistribution{}
	}

	return JsonDistribution{
		Name:    d.Name(),
		Version: d.FullVersion(),
		IDLike:  d.IDLike,
	}
}
