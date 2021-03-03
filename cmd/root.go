package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/event"
	"github.com/wagoodman/go-partybus"

	"github.com/anchore/syft/internal/config"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var persistentOpts = config.CliOnlyOptions{}

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
	rootCmd.PersistentFlags().StringVarP(&persistentOpts.ConfigPath, "config", "c", "", "application config file")

	flag := "quiet"
	rootCmd.PersistentFlags().BoolP(
		flag, "q", false,
		"suppress all logging output",
	)
	if err := viper.BindPFlag(flag, rootCmd.PersistentFlags().Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	rootCmd.PersistentFlags().CountVarP(&persistentOpts.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")

	// set common options that are not universal
	setFormatOptions(rootCmd.Flags())
	setUploadFlags(rootCmd.Flags())
	setSourceOptions(rootCmd.Flags())
}

func checkForApplicationUpdate() {
	if appConfig.CheckForAppUpdate {
		isAvailable, newVersion, err := version.IsUpdateAvailable()
		if err != nil {
			// this should never stop the application
			log.Errorf(err.Error())
		}
		if isAvailable {
			log.Infof("new version of %s is available: %s (current version is %s)", internal.ApplicationName, newVersion, version.FromBuild().Version)

			bus.Publish(partybus.Event{
				Type:  event.AppUpdateAvailable,
				Value: newVersion,
			})
		} else {
			log.Debugf("no new %s update available", internal.ApplicationName)
		}
	}
}
