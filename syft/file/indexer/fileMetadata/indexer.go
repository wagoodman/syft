package fileMetadata

import (
	"crypto"
	"fmt"
	"hash"
	"io"
	"strings"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

const Index = "fileMetadata"

var (
	_                       image.ContentObserver = (*Indexer)(nil)
	supportedHashAlgorithms                       = make(map[string]crypto.Hash)
)

type IndexerConfig struct {
	Resolver       source.FileLocationResolver
	HashAlgorithms []string
}

type Indexer struct {
	config  IndexerConfig
	catalog file.IndexCataloger
	hashes  []crypto.Hash
}

func init() {
	for _, h := range []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA256,
	} {
		lower := strings.ToLower(h.String())
		name := strings.Replace(lower, "-", "", -1)
		supportedHashAlgorithms[name] = h
	}
}

func NewIndexer(config IndexerConfig, catalog file.IndexCataloger) (*Indexer, error) {
	indexer := &Indexer{
		config:  config,
		catalog: catalog,
	}

	for _, hashStr := range config.HashAlgorithms {
		lowerHashStr := strings.ToLower(hashStr)
		hashObj, ok := supportedHashAlgorithms[lowerHashStr]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
		}
		indexer.hashes = append(indexer.hashes, hashObj)
	}

	return indexer, nil
}

func (i *Indexer) IsInterestedIn(ref stereoscopeFile.Reference) bool {
	return i.config.Resolver.HasFileLocation(source.NewLocationFromReference(ref))
}

func (i *Indexer) ObserveContent(subscription <-chan image.ContentObservation) {
	for entry := range subscription {
		// create a set of hasher objects tied together with a single writer to feed content into
		hashers := make([]hash.Hash, len(i.hashes))
		writers := make([]io.Writer, len(i.hashes))
		for idx, hashObj := range i.hashes {
			hashers[idx] = hashObj.New()
			writers[idx] = hashers[idx]
		}

		size, err := io.Copy(io.MultiWriter(writers...), entry.Content)
		if err != nil {
			log.Errorf("unable to observe contents of %+v: %+v", entry.Entry.File.RealPath, err)
		}

		result := file.Metadata{
			Mode: entry.Entry.Metadata.Mode,
			Type: file.NewTypeFromTarHeaderTypeFlag(entry.Entry.Metadata.TypeFlag),
			Uid:  entry.Entry.Metadata.UserID,
			Gid:  entry.Entry.Metadata.GroupID,
		}

		if size > 0 {
			// only capture digests when there is content. It is important to do this based on SIZE and not
			// FILE TYPE. The reasoning is that it is possible for a tar to be crafted with a header-only
			// file type but a body is still allowed.
			for idx, hasher := range hashers {
				result.Digests = append(result.Digests, file.Digest{
					Algorithm: i.hashes[idx].String(),
					Value:     fmt.Sprintf("%+x", hasher.Sum(nil)),
				})
			}
		}

		// capture results
		location := source.NewLocationFromReference(entry.Entry.File)
		i.catalog(location, result)

		// explicitly close the contents
		err = entry.Content.Close()
		if err != nil {
			log.Errorf("unable to close contents: %+v", entry.Entry.File.RealPath)
		}
	}
}
