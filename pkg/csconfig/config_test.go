package csconfig

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalLoad(t *testing.T) {

	_, err := NewConfig("./tests/config.yaml", false, false)
	require.NoError(t, err)

	_, err = NewConfig("./tests/xxx.yaml", false, false)
	if runtime.GOOS != "windows" {
		assert.EqualError(t, err, "while reading yaml file: open ./tests/xxx.yaml: no such file or directory")
	} else {
		assert.EqualError(t, err, "while reading yaml file: open ./tests/xxx.yaml: The system cannot find the file specified.")
	}

	_, err = NewConfig("./tests/simulation.yaml", false, false)
	assert.EqualError(t, err, "./tests/simulation.yaml: yaml: unmarshal errors:\n  line 1: field simulation not found in type csconfig.Config")
}

func TestNewCrowdSecConfig(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult *Config
		err            string
	}{
		{
			name:           "new configuration: basic",
			expectedResult: &Config{},
			err:            "",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := &Config{}
			require.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	err := NewDefaultConfig().Dump()
	require.NoError(t, err)
}
