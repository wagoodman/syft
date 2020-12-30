package file

import (
	"github.com/anchore/stereoscope/pkg/image"
)

type contentIterator interface {
	IterateContent(observers ...image.ContentObserver) error
}

type indexer struct {
	observers []image.ContentObserver
}

func newIndexer() indexer {
	return indexer{}
}

func (i *indexer) register(o image.ContentObserver) {
	i.observers = append(i.observers, o)
}

func (i *indexer) index(img contentIterator) error {
	return img.IterateContent(i.observers...)
}

func Index(img contentIterator, observers ...image.ContentObserver) error {
	i := newIndexer()
	for _, o := range observers {
		i.register(o)
	}
	return i.index(img)
}
