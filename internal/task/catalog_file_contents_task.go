package task

import (
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

func newCatalogFileContentsTask(appConfig config.Application) (Task, error) {
	if !appConfig.FileContents.Cataloger.Enabled {
		return nil, nil
	}

	contentsCataloger, err := file.NewContentsCataloger(appConfig.FileContents.Globs, appConfig.FileContents.SkipFilesAboveSize)
	if err != nil {
		return nil, err
	}

	task := func(results *Result, src source.Source) error {
		resolver, err := src.FileResolver(appConfig.FileContents.Cataloger.ScopeOpt)
		if err != nil {
			return err
		}

		result, err := contentsCataloger.Catalog(resolver)
		if err != nil {
			return err
		}
		results.FileContents = result
		return nil
	}

	return task, nil
}
