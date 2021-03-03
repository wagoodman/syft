package file

import "os"

type Metadata struct {
	Mode    os.FileMode `json:"mode"`
	Type    Type        `json:"type"`
	Uid     int         `json:"userID"`
	Gid     int         `json:"groupID"`
	Digests []Digest    `json:"digests"`
}

type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}
