/*
Defines a Presenter interface for displaying analysis results to an io.Writer as well as a helper utility to obtain
a specific Presenter implementation given user configuration.
*/
package presenter

import (
	"io"
)

// Presenter defines the expected behavior for an object responsible for displaying arbitrary input and processed data
// to a given io.Writer.
type Presenter interface {
	Present(io.Writer) error
}
