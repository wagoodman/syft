package task

import (
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

func newCatalogSecretsTask(appConfig config.Application) (Task, error) {
	if !appConfig.Secrets.Cataloger.Enabled {
		return nil, nil
	}

	patterns, err := file.GenerateSearchPatterns(file.DefaultSecretsPatterns, appConfig.Secrets.AdditionalPatterns, appConfig.Secrets.ExcludePatternNames)
	if err != nil {
		return nil, err
	}

	secretsCataloger, err := file.NewSecretsCataloger(patterns, appConfig.Secrets.RevealValues, appConfig.Secrets.SkipFilesAboveSize)
	if err != nil {
		return nil, err
	}

	task := func(results *Result, src source.Source) error {
		resolver, err := src.FileResolver(appConfig.Secrets.Cataloger.ScopeOpt)
		if err != nil {
			return err
		}

		result, err := secretsCataloger.Catalog(resolver)
		if err != nil {
			return err
		}
		results.Secrets = result
		return nil
	}

	return task, nil
}
