package yamlpatch

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

// verbatim from cstest, but cannot import it because of a circular import
func assertErrorContains(t *testing.T, err error, expectedErr string) {
	if expectedErr == "" {
		if err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
		assert.Equal(t, err, nil)
		return
	}
	if err == nil {
		t.Fatalf("Expected '%s', got nil", expectedErr)
	}
	assert.Contains(t, err.Error(), expectedErr)
}

func TestYAMLPatch(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		base        string
		patch       string
		expected    string
		expectedErr string
	}{
		{
			"notayaml",
			"",
			"",
			"/config.yaml: yaml: unmarshal errors:",
		},
		{
			"notayaml",
			"",
			"",
			"cannot unmarshal !!str `notayaml`",
		},
		{
			"",
			"notayaml",
			"",
			"/config.yaml.patch: yaml: unmarshal errors:",
		},
		{
			"",
			"notayaml",
			"",
			"cannot unmarshal !!str `notayaml`",
		},
		{
			"{'first':{'one':1,'two':2},'second':{'three':3}}",
			"{'first':{'one':10,'dos':2}}",
			"{'first':{'one':10,'dos':2,'two':2},'second':{'three':3}}",
			"",
		},
	}

	dirPath, err := os.MkdirTemp("", "yamlpatch")
	if err != nil {
		t.Fatal(err.Error())
	}
	defer os.RemoveAll(dirPath)
	configPath := filepath.Join(dirPath, "config.yaml")
	patchPath := filepath.Join(dirPath, "config.yaml.patch")

	for _, test := range tests {
		err = os.WriteFile(configPath, []byte(test.base), 0o644)
		if err != nil {
			t.Fatal(err.Error())
		}

		err = os.WriteFile(patchPath, []byte(test.patch), 0o644)
		if err != nil {
			t.Fatal(err.Error())
		}

		patcher := NewPatcher(configPath)
		patchedBytes, err := patcher.PatchedContent()
		assertErrorContains(t, err, test.expectedErr)
		assert.YAMLEq(test.expected, string(patchedBytes))
	}
}
