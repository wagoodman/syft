package cmd

import (
	"testing"

	"gotest.tools/assert"
)

func TestAttestCommandConstructor(t *testing.T) {
	cmd := Attest()
	assert.Equal(t, "attest", cmd.Use)
}
