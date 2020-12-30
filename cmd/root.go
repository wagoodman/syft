package cmd

import (
	"github.com/spf13/cobra"
)

// rootCmd is currently an alias for the packages command
var rootCmd = &cobra.Command{
	Short:         packagesCmd.Short,
	Long:          packagesCmd.Long,
	Args:          packagesCmd.Args,
	Example:       packagesCmd.Example,
	Deprecated:    "please use the 'packages' command instead\n",
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return packagesCmd.PreRunE(cmd, args)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		return packagesCmd.RunE(cmd, args)
	},
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return packagesCmd.ValidArgsFunction(cmd, args, toComplete)
	},
}

func init() {
	// set universal flags
	rootCmd.PersistentFlags().StringVarP(&cliOpts.ConfigPath, "config", "c", "", "application config file")

	// set common options that are not universal
	setFormatOptions(rootCmd.Flags())
	setUploadFlags(rootCmd.Flags())
	setSourceOptions(rootCmd.Flags())
}
