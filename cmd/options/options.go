package options

import "github.com/spf13/cobra"

type Interface interface {
	AddFlags(cmd *cobra.Command)
}
