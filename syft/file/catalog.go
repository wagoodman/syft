package file

import (
	"sync"

	"github.com/anchore/syft/syft/source"
)

type IndexCataloger func(location source.Location, metadata interface{})

type Catalog struct {
	catalog map[string]map[source.Location][]interface{}
	lock    *sync.RWMutex
}

func NewCatalog() *Catalog {
	return &Catalog{
		catalog: make(map[string]map[source.Location][]interface{}),
		lock:    &sync.RWMutex{},
	}
}

func (c *Catalog) NewIndexedCatalogEntryFactory(index string) IndexCataloger {
	return func(location source.Location, metadata interface{}) {
		c.addFileMetadata(index, location, metadata)
	}
}

func (c *Catalog) addFileMetadata(index string, location source.Location, metadata interface{}) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if _, ok := c.catalog[index]; !ok {
		c.catalog[index] = make(map[source.Location][]interface{})
	}

	c.catalog[index][location] = append(c.catalog[index][location], metadata)
}

func (c *Catalog) GetMetadata(index string, location source.Location) []interface{} {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if _, ok := c.catalog[index]; !ok {
		return nil
	}

	return c.catalog[index][location]
}

func (c *Catalog) GetLocations(index string) []source.Location {
	c.lock.RLock()
	defer c.lock.RUnlock()

	if _, ok := c.catalog[index]; !ok {
		return nil
	}

	var locations = make([]source.Location, len(c.catalog[index]))
	var idx int
	for l := range c.catalog[index] {
		locations[idx] = l
		idx++
	}
	return locations
}
