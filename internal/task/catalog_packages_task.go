package task

import (
	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/source"
)

func newCatalogPackagesTask(appConfig config.Application) (Task, error) {
	if !appConfig.Package.Cataloger.Enabled {
		return nil, nil
	}

	task := func(results *Result, src source.Source) error {
		packageCatalog, theDistro, err := syft.CatalogPackages(src, appConfig.Package.Cataloger.ScopeOpt)
		if err != nil {
			return err
		}

		results.PackageCatalog = packageCatalog
		results.Distro = theDistro

		return nil
	}

	return task, nil
}
