package csconfig

import (
	"path/filepath"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/stretchr/testify/require"
)

func TestLoadHub(t *testing.T) {
	hubFullPath, err := filepath.Abs("./hub")
	require.NoError(t, err)

	dataFullPath, err := filepath.Abs("./data")
	require.NoError(t, err)

	configDirFullPath, err := filepath.Abs("./tests")
	require.NoError(t, err)

	hubIndexFileFullPath, err := filepath.Abs("./hub/.index.json")
	require.NoError(t, err)

	tests := []struct {
		name           string
		Input          *Config
		expectedResult *Hub
		expectedErr    string
	}{
		{
			name: "basic valid configuration",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir:    "./tests",
					DataDir:      "./data",
					HubDir:       "./hub",
					HubIndexFile: "./hub/.index.json",
				},
			},
			expectedResult: &Hub{
				ConfigDir:    configDirFullPath,
				DataDir:      dataFullPath,
				HubDir:       hubFullPath,
				HubIndexFile: hubIndexFileFullPath,
			},
		},
		{
			name: "no data dir",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					ConfigDir:    "./tests",
					HubDir:       "./hub",
					HubIndexFile: "./hub/.index.json",
				},
			},
			expectedResult: nil,
		},
		{
			name:           "no configuration path",
			Input:          &Config{},
			expectedResult: nil,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadHub()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedResult == nil {
				return
			}

			require.Equal(t, tc.expectedResult, tc.Input.Hub)
		})
	}
}
