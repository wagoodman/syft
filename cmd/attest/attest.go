package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"os"

	"github.com/anchore/syft/cmd/options"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
)

func AttestCmd(ctx context.Context, ko sign.KeyOpts, certPath, predicateType, predicatePath, sbomPath string) error {
	// A key file is required

	// Parse Predicate
	predicateURI, err := options.ParsePredicateType(predicateType)
	if err != nil {
		return err
	}

	// get sbom reader
	sbombFile, err := os.Open(sbomPath)
	if err != nil {
		return err
	}
	defer sbombFile.Close()

	// parse sbom
	_, _, err = syft.Decode(sbombFile)
	if err != nil {
		return err
	}

	// Signer From Key
	sv, err := sign.SignerFromKeyOpts(ctx, certPath, ko)
	if err != nil {
		return err
	}
	defer sv.Close()
	wrapped := dsse.WrapSigner(sv, predicateURI)

	// Open Predicate
	predicate, err := os.Open(predicatePath)
	if err != nil {
		return err
	}

	// GenerateStatement
	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: predicate,
		Type:      predicateType,
		Digest:    "",
		Repo:      sbomPath,
	})
	if err != nil {
		return err
	}

	// marshal statement
	payload, err := json.Marshal(sh)
	if err != nil {
		return err
	}

	// sign statement
	signedPayload, err := wrapped.SignMessage(bytes.NewReader(payload))

	log.Info(signedPayload)
	// New Attestation

	// Attache Attestation to sbom
	log.Info("attesting provided sbom")
	return nil
}
