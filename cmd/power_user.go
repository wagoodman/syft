package cmd

import (
	"fmt"
	"os"

	"github.com/anchore/syft/internal/presenter/packages"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/ui"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/file/indexer/fileMetadata"
	"github.com/anchore/syft/syft/source"
	"github.com/gookit/color"
	"github.com/pkg/profile"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/wagoodman/go-partybus"
)

var powerUserOpts = struct {
	configPath string
}{}

var powerUserCmd = &cobra.Command{
	Use:           "power-user [SOURCE]",
	Short:         "Run bulk operations on container images",
	Example:       `  {{.appName}} power-user <image>`,
	Args:          cobra.ExactArgs(1),
	Hidden:        true,
	SilenceUsage:  true,
	SilenceErrors: true,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if appConfig.Dev.ProfileCPU && appConfig.Dev.ProfileMem {
			return fmt.Errorf("cannot profile CPU and memory simultaneously")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if appConfig.Dev.ProfileCPU {
			defer profile.Start(profile.CPUProfile).Stop()
		} else if appConfig.Dev.ProfileMem {
			defer profile.Start(profile.MemProfile).Stop()
		}

		return powerUserExec(cmd, args)
	},
	ValidArgsFunction: dockerImageValidArgsFunction,
}

func init() {
	powerUserCmd.Flags().StringVarP(&powerUserOpts.configPath, "config", "c", "", "config file path with all power-user options")
	if err := powerUserCmd.MarkFlagRequired("config"); err != nil {
		fmt.Printf("unable mark config flag as required: %+v", err)
		os.Exit(1)
	}

	rootCmd.AddCommand(powerUserCmd)
}

func powerUserExec(_ *cobra.Command, args []string) error {
	errs := powerUserExecWorker(args[0])
	ux := ui.Select(appConfig.CliOptions.Verbosity > 0, appConfig.Quiet)
	return ux(errs, eventSubscription)
}

func powerUserExecWorker(userInput string) <-chan error {
	errs := make(chan error)
	go func() {
		defer close(errs)

		powerUserConfig, err := config.LoadPowerUserConfig(viper.New(), powerUserOpts.configPath, *appConfig)
		if err != nil {
			errs <- err
			return
		}

		log.Debugf("power-user config:\n%s", color.Magenta.Sprint(powerUserConfig.String()))

		checkForApplicationUpdate()

		src, cleanup, err := source.New(userInput)
		if err != nil {
			errs <- err
			return
		}
		defer cleanup()

		if src.Metadata.Scheme != source.ImageScheme {
			errs <- fmt.Errorf("the power-user subcommand only allows for 'image' schemes, given %q", src.Metadata.Scheme)
			return
		}

		//if powerUserConfig.PackagesCataloger.Enabled {
		//	catalog, d, err := syft.CatalogPackages(src, powerUserConfig.PackagesCataloger.ScopeOpt)
		//	if err != nil {
		//		errs <- fmt.Errorf("failed to catalog input: %+v", err)
		//		return
		//	}
		//}

		_, err = runIndexers(*powerUserConfig, src)
		if err != nil {
			errs <- err
			return
		}

		//src, catalog, d, err := syft.Catalog(userInput, appConfig.ScopeOpt)
		//if err != nil {
		//	errs <- fmt.Errorf("failed to catalog input: %+v", err)
		//	return
		//}

		bus.Publish(partybus.Event{
			Type:  event.PresenterReady,
			Value: packages.Presenter(packages.JSONPresenterOption, packages.PresenterConfig{}),
		})
	}()
	return errs
}

func runIndexers(powerUserConfig config.PowerUser, theSource source.Source) (*file.Catalog, error) {
	// TODO: do config reading and validating... (for now just do exactly one cataloger, no cataloging)
	// TODO: derive IndexerConfig from a config file (viper preferred)... intermixed with other options
	// TODO: derive scope individually from each sub-config

	fileCatalog := file.NewCatalog()

	fileMetadataConfig := powerUserConfig.FileMetadataCataloger
	resolver, err := theSource.FileResolver(fileMetadataConfig.ScopeOpt)
	if err != nil {
		return nil, err
	}
	fileMetadataIndexerConfig := fileMetadata.IndexerConfig{
		Resolver:       resolver,
		HashAlgorithms: fileMetadataConfig.Digests,
	}
	fileMetadataIndexer, err := fileMetadata.NewIndexer(fileMetadataIndexerConfig, fileCatalog.NewIndexCataloger(fileMetadata.Index))
	if err != nil {
		return nil, fmt.Errorf("unable to create fileMetadata cataloger: %w", err)
	}

	indexers := []image.ContentObserver{
		fileMetadataIndexer,
	}

	if err = file.Index(theSource.Image, indexers...); err != nil {
		return nil, err
	}

	return fileCatalog, nil
}
