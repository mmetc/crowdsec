package csconfig

import (
	"path/filepath"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/stretchr/testify/require"
)

func TestLoadCSCLI(t *testing.T) {
	hubFullPath, err := filepath.Abs("./hub")
	if err != nil {
		t.Fatalf(err.Error())
	}

	dataFullPath, err := filepath.Abs("./data")
	if err != nil {
		t.Fatalf(err.Error())
	}

	configDirFullPath, err := filepath.Abs("./tests")
	if err != nil {
		t.Fatalf(err.Error())
	}

	hubIndexFileFullPath, err := filepath.Abs("./hub/.index.json")
	if err != nil {
		t.Fatalf(err.Error())
	}

	tests := []struct {
		name           string
		Input          *Config
		expectedResult *CscliCfg
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
			expectedResult: &CscliCfg{
				ConfigDir:    configDirFullPath,
				DataDir:      dataFullPath,
				HubDir:       hubFullPath,
				HubIndexFile: hubIndexFileFullPath,
			},
		},
		{
			name:           "no configuration path",
			Input:          &Config{},
			expectedResult: &CscliCfg{},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadCSCLI()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedErr == "" {
				return
			}

			require.Equal(t, tc.expectedResult, tc.Input.Cscli)
		})
	}
}
