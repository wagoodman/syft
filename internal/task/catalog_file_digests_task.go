package task

import (
	"crypto"
	"fmt"

	"github.com/anchore/syft/internal/config"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
)

func newFileDigestsTask(appConfig config.Application) (Task, error) {
	if !appConfig.FileMetadata.Cataloger.Enabled {
		return nil, nil
	}

	supportedHashAlgorithms := make(map[string]crypto.Hash)
	for _, h := range []crypto.Hash{
		crypto.MD5,
		crypto.SHA1,
		crypto.SHA256,
	} {
		supportedHashAlgorithms[file.DigestAlgorithmName(h)] = h
	}

	var hashes []crypto.Hash
	for _, hashStr := range appConfig.FileMetadata.Digests {
		name := file.CleanDigestAlgorithmName(hashStr)
		hashObj, ok := supportedHashAlgorithms[name]
		if !ok {
			return nil, fmt.Errorf("unsupported hash algorithm: %s", hashStr)
		}
		hashes = append(hashes, hashObj)
	}

	digestsCataloger, err := file.NewDigestsCataloger(hashes)
	if err != nil {
		return nil, err
	}

	task := func(results *Result, src source.Source) error {
		resolver, err := src.FileResolver(appConfig.FileMetadata.Cataloger.ScopeOpt)
		if err != nil {
			return err
		}

		result, err := digestsCataloger.Catalog(resolver)
		if err != nil {
			return err
		}
		results.FileDigests = result
		return nil
	}

	return task, nil
}
