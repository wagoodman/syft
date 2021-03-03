package source

import (
	"io"
)

// FileResolver is an interface that encompasses how to get specific file references and file contents for a generic data source.
type FileResolver interface {
	FileContentResolver
	FilePathResolver
	FileLocationResolver
}

// FileContentResolver knows how to get file content for given file.References
type FileContentResolver interface {
	FileContentsByLocation(Location) (io.ReadCloser, error)
	// TODO: it is possible to be given duplicate locations that will be overridden in the map (key), a subtle problem that coule easily be misued.
	MultipleFileContentsByLocation([]Location) (map[Location]io.ReadCloser, error)
}

// FilePathResolver knows how to get a Location for given string paths and globs
type FilePathResolver interface {
	// HasPath indicates if the given path exists in the underlying source.
	HasPath(string) bool
	// FilesByPath fetches a set of file references which have the given path (for an image, there may be multiple matches)
	FilesByPath(paths ...string) ([]Location, error)
	// FilesByGlob fetches a set of file references which the given glob matches
	FilesByGlob(patterns ...string) ([]Location, error)
	// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
	// This is helpful when attempting to find a file that is in the same layer or lower as another file.
	RelativeFileByPath(_ Location, path string) *Location
}

type FileLocationResolver interface {
	HasLocation(Location) bool
}
