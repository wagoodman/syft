package packages

import "github.com/anchore/syft/syft/pkg"

type JsonRelationship struct {
	Parent   string      `json:"parent"`
	Child    string      `json:"child"`
	Type     string      `json:"type"`
	Metadata interface{} `json:"metadata"`
}

func newJsonRelationships(relationships []pkg.Relationship) []JsonRelationship {
	result := make([]JsonRelationship, len(relationships))
	for i, r := range relationships {
		result[i] = JsonRelationship{
			Parent:   string(r.Parent),
			Child:    string(r.Child),
			Type:     string(r.Type),
			Metadata: r.Metadata,
		}
	}
	return result
}
