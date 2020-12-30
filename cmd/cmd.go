package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/anchore/stereoscope"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/logger"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/presenter"
	"github.com/anchore/syft/syft/source"
	"github.com/gookit/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
)

var appConfig *config.Application
var eventBus *partybus.Bus
var eventSubscription *partybus.Subscription
var cliOpts = config.CliOnlyOptions{}

func init() {
	cobra.OnInitialize(
		initAppConfig,
		initLogging,
		logAppConfig,
		initEventBus,
	)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, color.Red.Sprint(err.Error()))
		os.Exit(1)
	}
}

func setSourceOptions(flags *pflag.FlagSet) {
	flag := "scope"
	flags.StringP(
		"scope", "s", source.SquashedScope.String(),
		fmt.Sprintf("selection of layers to catalog, options=%v", source.AllScopes))
	if err := viper.BindPFlag(flag, flags.Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}
}

func setFormatOptions(flags *pflag.FlagSet) {
	// output & formatting options
	flag := "output"
	flags.StringP(
		flag, "o", string(presenter.TablePresenter),
		fmt.Sprintf("report output formatter, options=%v", presenter.Options),
	)
	if err := viper.BindPFlag(flag, flags.Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = "quiet"
	flags.BoolP(
		flag, "q", false,
		"suppress all logging output",
	)
	if err := viper.BindPFlag(flag, flags.Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flags.CountVarP(&cliOpts.Verbosity, "verbose", "v", "increase verbosity (-v = info, -vv = debug)")
}

func setUploadFlags(flags *pflag.FlagSet) {
	flag := "host"
	flags.StringP(
		flag, "H", "",
		"the hostname or URL of the Anchore Enterprise instance to upload to",
	)
	if err := viper.BindPFlag("anchore.host", flags.Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = "username"
	flags.StringP(
		flag, "u", "",
		"the username to authenticate against Anchore Enterprise",
	)
	if err := viper.BindPFlag("anchore.username", flags.Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = "password"
	flags.StringP(
		flag, "p", "",
		"the password to authenticate against Anchore Enterprise",
	)
	if err := viper.BindPFlag("anchore.password", flags.Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '%s': %+v", flag, err)
		os.Exit(1)
	}

	flag = "dockerfile"
	flags.StringP(
		flag, "d", "",
		"include dockerfile for upload to Anchore Enterprise",
	)
	if err := viper.BindPFlag("anchore.dockerfile", flags.Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '#{flag}': #{err}")
		os.Exit(1)
	}

	flag = "overwrite-existing-image"
	flags.Bool(
		flag, false,
		"overwrite an existing image during the upload to Anchore Enterprise",
	)
	if err := viper.BindPFlag("anchore.overwrite-existing-image", flags.Lookup(flag)); err != nil {
		fmt.Printf("unable to bind flag '#{flag}': #{err}")
		os.Exit(1)
	}
}

func initAppConfig() {
	cfgVehicle := viper.GetViper()
	wasHostnameSet := rootCmd.Flags().Changed("host")
	cfg, err := config.LoadApplicationConfig(cfgVehicle, cliOpts, wasHostnameSet)
	if err != nil {
		fmt.Printf("failed to load application config: \n\t%+v\n", err)
		os.Exit(1)
	}

	appConfig = cfg
}

func initLogging() {
	cfg := logger.LogrusConfig{
		EnableConsole: (appConfig.Log.FileLocation == "" || appConfig.CliOptions.Verbosity > 0) && !appConfig.Quiet,
		EnableFile:    appConfig.Log.FileLocation != "",
		Level:         appConfig.Log.LevelOpt,
		Structured:    appConfig.Log.Structured,
		FileLocation:  appConfig.Log.FileLocation,
	}

	logWrapper := logger.NewLogrusLogger(cfg)
	syft.SetLogger(logWrapper)
	stereoscope.SetLogger(&logger.LogrusNestedLogger{
		Logger: logWrapper.Logger.WithField("from-lib", "stereoscope"),
	})
}

func logAppConfig() {
	log.Debugf("Application config:\n%+v", color.Magenta.Sprint(appConfig.String()))
}

func initEventBus() {
	eventBus = partybus.NewBus()
	eventSubscription = eventBus.Subscribe()

	stereoscope.SetBus(eventBus)
	syft.SetBus(eventBus)
}
