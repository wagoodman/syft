package packages

import (
	"github.com/anchore/syft/internal/presenter"
)

// Presenter returns an object that can present the result of the "packages" subcommand.
func Presenter(option PresenterOption, config PresenterConfig) presenter.Presenter {
	switch option {
	case JSONPresenterOption:
		return NewJSONPresenter(config.Catalog, config.SourceMetadata, config.Distro)
	case TextPresenterOption:
		return NewTextPresenter(config.Catalog, config.SourceMetadata)
	case TablePresenterOption:
		return NewTablePresenter(config.Catalog)
	case CycloneDxPresenterOption:
		return NewCycloneDxPresenter(config.Catalog, config.SourceMetadata)
	default:
		return nil
	}
}
