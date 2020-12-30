package cmd

import (
	"fmt"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/syft/syft/source"

	"github.com/anchore/syft/syft/file/indexer/digest"

	"github.com/pkg/profile"
	"github.com/spf13/cobra"
)

var powerUserCmd = &cobra.Command{
	Use:           "power-user [SOURCE]",
	Short:         "Run bulk operations on container images",
	Example:       `  {{.appName}} power-user config.yaml <image>`,
	Args:          cobra.ExactArgs(1), // TODO: make this 2
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
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		// Since we use ValidArgsFunction, Cobra will call this AFTER having parsed all flags and arguments provided
		dockerImageRepoTags, err := listLocalDockerImages(toComplete)
		if err != nil {
			// Indicates that an error occurred and completions should be ignored
			return []string{"completion failed"}, cobra.ShellCompDirectiveError
		}
		if len(dockerImageRepoTags) == 0 {
			return []string{"no docker images found"}, cobra.ShellCompDirectiveError
		}
		// ShellCompDirectiveDefault indicates that the shell will perform its default behavior after completions have
		// been provided (without implying other possible directives)
		return dockerImageRepoTags, cobra.ShellCompDirectiveDefault
	},
}

func init() {
	// add the subcommand
	rootCmd.AddCommand(powerUserCmd)
}

func powerUserExec(cmd *cobra.Command, args []string) error {
	// TODO: do config reading and validating... (for now just do exactly one indexer, no cataloging)
	// TODO: derive IndexerConfig from a config file (viper preferred)... intermixed with other options
	// TODO: derive scope individually from each sub-config

	theSource, cleanup, err := source.New(args[0], appConfig.ScopeOpt)
	defer cleanup()
	if err != nil {
		return err
	}

	digestConfig := digest.IndexerConfig{
		Resolver: theSource.Resolver,
	}
	digestIndexer := digest.NewIndexer(digestConfig)

	if err = file.Index(theSource.Image, digestIndexer); err != nil {
		return err
	}

	// TODO: hook into existing presenter abstraction
	return nil
}
