package csconfig_test

import (
	"path/filepath"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
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
		name        string
		Input       *csconfig.Config
		expected    *csconfig.Hub
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			Input: &csconfig.Config{
				ConfigPaths: &csconfig.ConfigurationPaths{
					ConfigDir:    "./tests",
					DataDir:      "./data",
					HubDir:       "./hub",
					HubIndexFile: "./hub/.index.json",
				},
			},
			expected: &csconfig.Hub{
				ConfigDir:    configDirFullPath,
				DataDir:      dataFullPath,
				HubDir:       hubFullPath,
				HubIndexFile: hubIndexFileFullPath,
			},
		},
		{
			name: "no data dir",
			Input: &csconfig.Config{
				ConfigPaths: &csconfig.ConfigurationPaths{
					ConfigDir:    "./tests",
					HubDir:       "./hub",
					HubIndexFile: "./hub/.index.json",
				},
			},
			expectedErr:    "please provide a data directory with the 'data_dir' directive in the 'config_paths' section",
		},
		{
			name:           "no configuration path",
			Input:          &csconfig.Config{},
			expectedErr:    "no configuration paths provided",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadHub()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expected == nil {
				return
			}

			require.Equal(t, tc.expected, tc.Input.Hub)
		})
	}
}
