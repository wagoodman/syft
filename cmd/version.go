package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/version"
	"github.com/anchore/syft/syft/presenter"
	"github.com/spf13/cobra"
)

var outputFormat string

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "show the version",
	RunE:  versionExec,
}

func init() {
	versionCmd.Flags().StringVarP(&outputFormat, "output", "o", string(presenter.TextPresenter), "format to show version information (available=[text, json])")
	rootCmd.AddCommand(versionCmd)
}

func versionExec(_ *cobra.Command, _ []string) error {
	versionInfo := version.FromBuild()

	switch outputFormat {
	case "text":
		fmt.Println("Application:  ", internal.ApplicationName)
		fmt.Println("Version:      ", versionInfo.Version)
		fmt.Println("BuildDate:    ", versionInfo.BuildDate)
		fmt.Println("GitCommit:    ", versionInfo.GitCommit)
		fmt.Println("GitTreeState: ", versionInfo.GitTreeState)
		fmt.Println("Platform:     ", versionInfo.Platform)
		fmt.Println("GoVersion:    ", versionInfo.GoVersion)
		fmt.Println("Compiler:     ", versionInfo.Compiler)

	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", " ")
		err := enc.Encode(&struct {
			version.Version
			Application string `json:"application"`
		}{
			Version:     versionInfo,
			Application: internal.ApplicationName,
		})
		if err != nil {
			return fmt.Errorf("failed to show version information: %w", err)
		}
	default:
		return fmt.Errorf("unsupported output format: %s", outputFormat)
	}
	return nil
}
