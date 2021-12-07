package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	cattest "github.com/sigstore/cosign/cmd/cosign/cli/attest"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"

	ociremote "github.com/sigstore/cosign/pkg/oci/remote"
)

type AttestConfiguration struct {
	ImageRef      string
	CertPath      string
	PredicatePath string
	PredicateType string
	Ko            sign.KeyOpts
	RegOpts       options.RegistryOptions
}

func AttestCmd(ctx context.Context, ac *AttestConfiguration) error {
	// A key file is required
	predicateURI, err := options.ParsePredicateType(ac.PredicateType)
	if err != nil {
		return err
	}

	ref, err := name.ParseReference(ac.ImageRef)
	if err != nil {
		return err
	}

	ociremoteOpts, err := ac.RegOpts.ClientOpts(ctx)
	if err != nil {
		return err
	}

	digest, err := ociremote.ResolveDigest(ref, ociremoteOpts...)
	if err != nil {
		return err
	}

	h, _ := v1.NewHash(digest.Identifier())
	ref = digest

	attestor, _, closeFn, err := cattest.AttestorFromKeyOpts(ctx, ac.CertPath, predicateURI, ac.Ko)
	if err != nil {
		return errors.Wrap(err, "getting signer")
	}
	if closeFn != nil {
		defer closeFn()
	}

	fmt.Fprintln(os.Stderr, "Using payload from:", ac.PredicatePath)
	predicate, err := os.Open(ac.PredicatePath)
	if err != nil {
		return err
	}
	defer predicate.Close()

	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: predicate,
		Type:      ac.PredicateType,
		Digest:    h.Hex,
		Repo:      digest.Repository.String(),
	})
	if err != nil {
		return err
	}

	payload, err := json.Marshal(sh)
	if err != nil {
		return err
	}

	ociAtt, _, err := attestor.Attest(ctx, bytes.NewReader(payload))
	if err != nil {
		return err
	}

	signedPayload, err := ociAtt.Payload()
	if err != nil {
		return err
	}

	fmt.Println(string(signedPayload))
	return nil
}
