package csconfig_test

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
)

func TestNormalLoad(t *testing.T) {
	_, err := csconfig.NewConfig("./tests/config.yaml", false, false)
	require.NoError(t, err)

	_, err = csconfig.NewConfig("./tests/xxx.yaml", false, false)
	if runtime.GOOS != "windows" {
		assert.EqualError(t, err, "while reading yaml file: open ./tests/xxx.yaml: no such file or directory")
	} else {
		assert.EqualError(t, err, "while reading yaml file: open ./tests/xxx.yaml: The system cannot find the file specified.")
	}

	_, err = csconfig.NewConfig("./tests/simulation.yaml", false, false)
	assert.EqualError(t, err, "./tests/simulation.yaml: yaml: unmarshal errors:\n  line 1: field simulation not found in type csconfig.Config")
}

func TestNewCrowdSecConfig(t *testing.T) {
	tests := []struct {
		name           string
		expectedResult *csconfig.Config
		err            string
	}{
		{
			name:           "new configuration: basic",
			expectedResult: &csconfig.Config{},
			err:            "",
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := &csconfig.Config{}
			require.Equal(t, tc.expectedResult, result)
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	err := csconfig.NewDefaultConfig().Dump()
	require.NoError(t, err)
}
