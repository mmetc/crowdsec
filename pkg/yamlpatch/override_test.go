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

func TestOverride(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		base        string
		over        string
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
			"/config.yaml.override: yaml: unmarshal errors:",
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

	dirPath, err := os.MkdirTemp("", "override")
	if err != nil {
		t.Fatal(err.Error())
	}
	defer os.RemoveAll(dirPath)
	configPath := filepath.Join(dirPath, "config.yaml")
	overridePath := filepath.Join(dirPath, "config.yaml.override")

	for _, test := range tests {
		err = os.WriteFile(configPath, []byte(test.base), 0o644)
		if err != nil {
			t.Fatal(err.Error())
		}

		err = os.WriteFile(overridePath, []byte(test.over), 0o644)
		if err != nil {
			t.Fatal(err.Error())
		}

		var merged []byte
		merged, err = PatchedYAML(configPath)
		assertErrorContains(t, err, test.expectedErr)
		assert.YAMLEq(string(merged), test.expected)
	}
}
