package yamlpatch

import (
	"os"

	"github.com/imdario/mergo"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type Patcher struct {
	BaseFilePath  string
	PatchFilePath string
}

func NewPatcher(filePath string) *Patcher {
	yamlpatcher := Patcher{
		BaseFilePath:  filePath,
		PatchFilePath: filePath + ".patch",
	}

	return &yamlpatcher
}

// reads a single YAML file and returns a map that can be serialized later
func readYAML(filePath string) (map[interface{}]interface{}, error) {
	var yamlMap map[interface{}]interface{}
	var content []byte
	var err error

	if content, err = os.ReadFile(filePath); err != nil {
		return nil, err
	}

	if err = yaml.Unmarshal(content, &yamlMap); err != nil {
		return nil, errors.Wrap(err, filePath)
	}

	return yamlMap, nil
}

// PatchedContent reads a YAML file and, if it exists, its '.patch' file, then
// merges them and returns it serialized
func (p *Patcher) PatchedContent() ([]byte, error) {
	var err error
	var base map[interface{}]interface{}
	var over map[interface{}]interface{}

	base, err = readYAML(p.BaseFilePath)
	if err != nil {
		return nil, err
	}

	over, err = readYAML(p.PatchFilePath)
	if err != nil {
		// optional file, ignore if it does not exist
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
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
