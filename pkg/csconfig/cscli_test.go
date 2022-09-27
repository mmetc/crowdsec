package csconfig_test

import (
	"path/filepath"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/stretchr/testify/require"
)

func TestLoadCSCLI(t *testing.T) {
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
		expected    *csconfig.CscliCfg
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
			expected: &csconfig.CscliCfg{
				ConfigDir:    configDirFullPath,
				DataDir:      dataFullPath,
				HubDir:       hubFullPath,
				HubIndexFile: hubIndexFileFullPath,
			},
		},
		{
			name:        "no configuration path",
			Input:       &csconfig.Config{},
			expectedErr: "no configuration paths provided",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadCSCLI()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedErr != "" {
				return
			}

			require.Equal(t, tc.expected, tc.Input.Cscli)
		})
	}
}
