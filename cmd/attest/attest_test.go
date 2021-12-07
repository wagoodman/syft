package attest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAttest(t *testing.T) {
	tests := []struct {
		name      string
		ac        *AttestConfiguration
		shouldErr bool
	}{
		{
			name:      "Attest takes an oci image and appends an attestation to its digest",
			ac:        &AttestConfiguration{},
			shouldErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.TODO()
			err := AttestCmd(ctx, tt.ac)
			if tt.shouldErr {
				// TODO: Add error cases
			}
			require.NoError(t, err, "%s should not return an err: %v", tt.name, err)
		})
	}
}
