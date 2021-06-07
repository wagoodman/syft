package task

import (
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

func newClassifyFilesTask(appConfig config.Application) (Task, error) {
	if !appConfig.FileClassification.Cataloger.Enabled {
		return nil, nil
	}

	// TODO: in the future we could expose out the classifiers via configuration
	classifierCataloger, err := file.NewClassificationCataloger(file.DefaultClassifiers)
	if err != nil {
		return nil, err
	}

	task := func(results *Result, src source.Source) error {
		resolver, err := src.FileResolver(appConfig.FileClassification.Cataloger.ScopeOpt)
		if err != nil {
			return err
		}

		result, err := classifierCataloger.Catalog(resolver)
		if err != nil {
			return err
		}
		results.FileClassifications = result
		return nil
	}

	return task, nil
}
