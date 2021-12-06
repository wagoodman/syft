package options

import (
	"fmt"
	"net/url"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/spf13/cobra"
)

const (
	PredicateLink = "link"
)

// PredicateTypeMap is the mapping between the predicate `type` option to predicate URI.
var PredicateTypeMap = map[string]string{
	PredicateLink: in_toto.PredicateLinkV1,
}

type PredicateOptions struct {
	Type string
}

var _ Interface = (*PredicateOptions)(nil)

// AddFlags implements Interface
func (o *PredicateOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Type, "type", "custom",
		"specify a predicate type (slsaprovenance|link|spdx|custom) or an URI")
}

// ParsePredicateType parses the predicate `type` flag passed into a predicate URI, or validates `type` is a valid URI.
func ParsePredicateType(t string) (string, error) {
	uri, ok := PredicateTypeMap[t]
	if !ok {
		if _, err := url.ParseRequestURI(t); err != nil {
			return "", fmt.Errorf("invalid predicate type: %s", t)
		}
		uri = t
	}
	return uri, nil
}

// PredicateLocalOptions is the wrapper for predicate related options.
type PredicateLocalOptions struct {
	PredicateOptions
	Path string
}

var _ Interface = (*PredicateLocalOptions)(nil)

// AddFlags implements Interface
func (o *PredicateLocalOptions) AddFlags(cmd *cobra.Command) {
	o.PredicateOptions.AddFlags(cmd)

	cmd.Flags().StringVar(&o.Path, "predicate", "",
		"path to the predicate file.")
}
