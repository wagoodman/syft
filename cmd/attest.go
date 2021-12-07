package cmd

import (
	"github.com/anchore/syft/cmd/attest"
	"github.com/anchore/syft/cmd/options"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/generate"
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
		Example: `syft attest --key <key path> [--predicate <path>] [--a key=value] <image>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, img := range args {
				ac := &attest.AttestConfiguration{
					ImageRef:      img,
					PredicatePath: o.Predicate.Path,
					PredicateType: o.Predicate.Type,
					Ko: sign.KeyOpts{
						KeyRef:   o.Key,
						PassFunc: generate.GetPass,
					},
				}
				if err := attest.AttestCmd(cmd.Context(), ac); err != nil {
					return errors.Wrapf(err, "signing %s", img)
				}
			}

			return nil
		},
	}

	o.AddFlags(cmd)

	return cmd
}
