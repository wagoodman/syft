package task

import (
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/source"
)

var factoriesByProduct = map[Product]Factory{
	PackagesProduct:            newCatalogPackagesTask,
	FileMetadataProduct:        newCatalogFileMetadataTask,
	FileDigestsProduct:         newFileDigestsTask,
	FileClassificationsProduct: newClassifyFilesTask,
	FileContentsProduct:        newCatalogFileContentsTask,
	SecretsProduct:             newCatalogSecretsTask,
}

type Task func(*Result, source.Source) error

type Factory func(config.Application) (Task, error)
