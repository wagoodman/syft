package integration

import (
	"testing"
)

func TestJavaNoMainPackage(t *testing.T) { // Regression: https://github.com/anchore/syft/issues/252
	catalogFixtureImage(t, "image-java-no-main-package")
}
