package file

import (
	"github.com/anchore/stereoscope/pkg/image"
)

type contentIterator interface {
	IterateContent(observers ...image.ContentObserver) error
}

func Index(img contentIterator, observers ...image.ContentObserver) error {
	return img.IterateContent(observers...)
}
