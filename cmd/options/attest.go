package options

import "github.com/spf13/cobra"

type AttestOptions struct {
	Key       string
	Cert      string
	Predicate PredicateLocalOptions
}

var _ Interface = (*AttestOptions)(nil)

func (o *AttestOptions) AddFlags(cmd *cobra.Command) {
	o.Predicate.AddFlags(cmd)
	cmd.Flags().StringVar(&o.Key, "key", "", "path to the private key file")
	cmd.Flags().StringVar(&o.Cert, "cert", "",
		"path to the x509 certificate to include in the Signature")

}
