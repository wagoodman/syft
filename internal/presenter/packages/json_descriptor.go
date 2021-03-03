package packages

// JSONDescriptor describes what created the document as well as surrounding metadata
type JSONDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
