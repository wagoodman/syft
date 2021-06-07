package task

import (
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

func newCatalogFileMetadataTask(appConfig config.Application) (Task, error) {
	if !appConfig.FileMetadata.Cataloger.Enabled {
		return nil, nil
	}

	metadataCataloger := file.NewMetadataCataloger()

	task := func(results *Result, src source.Source) error {
		resolver, err := src.FileResolver(appConfig.FileMetadata.Cataloger.ScopeOpt)
		if err != nil {
			return err
		}

		result, err := metadataCataloger.Catalog(resolver)
		if err != nil {
			return err
		}
		results.FileMetadata = result
		return nil
	}

	return task, nil
}
