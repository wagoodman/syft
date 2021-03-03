package config

import (
	"fmt"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

type PowerUser struct {
	ConfigPath            string                `yaml:"configPath"`
	PackagesCataloger     PackageCataloger      `yaml:"packageCataloger" mapstructure:"packageCataloger"`
	FileMetadataCataloger FileMetadataCataloger `yaml:"fileMetadataCataloger" mapstructure:"fileMetadataCataloger"`
}

// LoadPowerUserConfig populates the given viper object with PowerUser configuration  on disk
func LoadPowerUserConfig(v *viper.Viper, configPath string, appConfig Application) (*PowerUser, error) {
	setDefaultPowerUserConfigValues(v, appConfig)

	v.AutomaticEnv()
	v.SetEnvPrefix(internal.ApplicationName + "_POWER_USER")
	// allow for nested options to be specified via environment variables
	// e.g. pod.context = APPNAME_POD_CONTEXT
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	// use explicitly the given user config
	v.SetConfigFile(configPath)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("unable to read power-user config=%q : %w", configPath, err)
	}

	config := &PowerUser{}
	if err := v.Unmarshal(config); err != nil {
		return nil, fmt.Errorf("unable to parse power-user config: %w", err)
	}
	config.ConfigPath = v.ConfigFileUsed()

	if err := config.build(); err != nil {
		return nil, fmt.Errorf("invalid power-user config: %w", err)
	}

	return config, nil
}

// build inflates simple config values into native objects after the config is fully read in.
func (cfg *PowerUser) build() error {
	if err := cfg.FileMetadataCataloger.build(); err != nil {
		return err
	}
	return nil
}

func (cfg PowerUser) String() string {
	cfgStr, err := yaml.Marshal(&cfg)
	if err != nil {
		return err.Error()
	}
	return string(cfgStr)
}

// setDefaultPowerUserConfigValues ensures that there are sane defaults for values that do not have CLI equivalent options (where there would already be a default value)
func setDefaultPowerUserConfigValues(v *viper.Viper, appConfig Application) {
	// set file metadata default options
	v.SetDefault("fileMetadataCataloger.enabled", true)
	//v.SetDefault("fileMetadata.files", []string{"**"}) // TODO: an empty list should mean all files, yes? helps on performance
	v.SetDefault("fileMetadataCataloger.scope", appConfig.Scope)
	v.SetDefault("fileMetadataCataloger.digests", []string{"sha256"})
}
