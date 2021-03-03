package packages

import (
	"encoding/json"
	"fmt"

	"github.com/anchore/syft/syft/source"
)

// Source object represents the thing that was cataloged
type JSONSource struct {
	Type   string      `json:"type"`
	Target interface{} `json:"target"`
}

// jsonSourceUnpacker is used to unmarshal Source objects
type jsonSourceUnpacker struct {
	Type   string          `json:"type"`
	Target json.RawMessage `json:"target"`
}

// NewJSONSource creates a new source object to be represented into JSON.
func NewJSONSource(src source.Metadata) (JSONSource, error) {
	switch src.Scheme {
	case source.ImageScheme:
		return JSONSource{
			Type:   "image",
			Target: src.ImageMetadata,
		}, nil
	case source.DirectoryScheme:
		return JSONSource{
			Type:   "directory",
			Target: src.Path,
		}, nil
	default:
		return JSONSource{}, fmt.Errorf("unsupported source: %T", src)
	}
}

// UnmarshalJSON populates a source object from JSON bytes.
func (s *JSONSource) UnmarshalJSON(b []byte) error {
	var unpacker jsonSourceUnpacker
	if err := json.Unmarshal(b, &unpacker); err != nil {
		return err
	}

	s.Type = unpacker.Type

	switch s.Type {
	case "image":
		var payload source.ImageMetadata
		if err := json.Unmarshal(unpacker.Target, &payload); err != nil {
			return err
		}
		s.Target = payload
	default:
		return fmt.Errorf("unsupported package metadata type: %+v", s.Type)
	}

	return nil
}

// ToSourceMetadata takes a source object represented from JSON and creates a source.Metadata object.
func (s *JSONSource) ToSourceMetadata() source.Metadata {
	var metadata source.Metadata
	switch s.Type {
	case "directory":
		metadata.Scheme = source.DirectoryScheme
		metadata.Path = s.Target.(string)
	case "image":
		metadata.Scheme = source.ImageScheme
		metadata.ImageMetadata = s.Target.(source.ImageMetadata)
	}
	return metadata
}
