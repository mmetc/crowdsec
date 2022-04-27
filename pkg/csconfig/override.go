package csconfig

// with yaml v3:
// https://stackoverflow.com/questions/65768861/read-and-merge-two-yaml-files-dynamically-and-or-recursively

import (
	"os"

	"github.com/pkg/errors"

	"github.com/imdario/mergo"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

func mergedYAML(filePath string) ([]byte, error) {
	var err error
	basePath := filePath
	overPath := filePath + ".override"

	var baseContent []byte
	if baseContent, err = os.ReadFile(basePath); err != nil {
		return nil, err
	}

	var base map[interface{}]interface{}
	log.Debugf("Unmarshaling %s", basePath)
	err = yaml.Unmarshal(baseContent, &base)
	if err != nil {
		return nil, errors.Wrap(err, basePath)
	}

	var overContent []byte
	if overContent, err = os.ReadFile(overPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}

	var over map[interface{}]interface{}
	log.Debugf("Unmarshaling %s", overPath)
	err = yaml.Unmarshal(overContent, &over)
	if err != nil {
		return nil, errors.Wrap(err, overPath)
	}

	if err := mergo.Merge(&over, base); err != nil {
		return nil, err
	}

	var merged []byte
	merged, err = yaml.Marshal(&over)
	if err != nil {
		return nil, err
	}
	return merged, nil
}
