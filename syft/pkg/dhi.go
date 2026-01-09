package pkg

// DHISBOMEntry represents all captured data from Docker Hardened Images (DHI) packages
// described in DHI's SPDX files found at /opt/docker/sbom/.
type DHISBOMEntry struct {
	// Name is the package name as found in the DHI SPDX file
	Name string `mapstructure:"name" json:"name"`

	// Version is the package version as found in the DHI SPDX file
	Version string `mapstructure:"version" json:"version"`

	// Platform is the target platform (e.g., linux/arm64)
	Platform string `mapstructure:"platform" json:"platform,omitempty"`

	// OSName is the operating system name (e.g., debian)
	OSName string `mapstructure:"osName" json:"osName,omitempty"`

	// OSVersion is the operating system version (e.g., 13)
	OSVersion string `mapstructure:"osVersion" json:"osVersion,omitempty"`
}

func (d DHISBOMEntry) OwnedFiles() []string {
	return nil
}
