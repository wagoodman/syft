package digest

import (
	"fmt"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/syft/source"
)

var _ image.ContentObserver = (*Indexer)(nil)

type IndexerConfig struct {
	Resolver source.FileResolver
}

type Indexer struct {
	config IndexerConfig
}

func NewIndexer(config IndexerConfig) *Indexer {
	return &Indexer{
		config: config,
	}
}

func (i *Indexer) IsInterestedIn(ref file.Reference) bool {
	locations, err := i.config.Resolver.FilesByPath(string(ref.RealPath))
	if err != nil {
		return false
	}
	for _, l := range locations {
		if l.Reference == ref {
			return true
		}
	}
	return false
}

func (i *Indexer) ObserveContent(subscription <-chan image.ContentObservation) {
	for x := range subscription {
		// TODO: this is where we would read the contents and record the digest onto the indexer object
		fmt.Printf("Observation: %+v\n", x.Entry.File)
		x.Content.Close()
	}
}
