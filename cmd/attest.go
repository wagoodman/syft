package cmd

import (
	"github.com/anchore/syft/cmd/attest"
	"github.com/anchore/syft/cmd/options"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(Attest())
}

func Attest() *cobra.Command {
	o := &options.AttestOptions{}

	cmd := &cobra.Command{
		Use:     "attest",
		Short:   "Attest the supplied sbom.",
		Example: `syft attest --key <key path> [--predicate <path>] [--a key=value] <sbom file>`,
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ko := sign.KeyOpts{
				KeyRef: o.Key,
			}

			for _, sbom := range args {
				if err := attest.AttestCmd(cmd.Context(), ko, o.Cert, o.Predicate.Type, o.Predicate.Path, sbom); err != nil {
					return errors.Wrapf(err, "signing %s", sbom)
				}
			}

			return nil
		},
	}

	o.AddFlags(cmd)

	return cmd
}
