package csconfig_test

import (
	"path/filepath"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestLoadCrowdsec(t *testing.T) {
	falseBoolPtr := false
	acquisFullPath, err := filepath.Abs("./tests/acquis.yaml")
	require.NoError(t, err)

	acquisInDirFullPath, err := filepath.Abs("./tests/acquis/acquis.yaml")
	require.NoError(t, err)

	acquisDirFullPath, err := filepath.Abs("./tests/acquis")
	require.NoError(t, err)

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
		expected    *csconfig.CrowdsecServiceCfg
		expectedErr string
	}{
		{
			name: "basic valid configuration",
			Input: &csconfig.Config{
				ConfigPaths: &csconfig.ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &csconfig.APICfg{
					Client: &csconfig.LocalApiClientCfg{
						CredentialsFilePath: "./tests/lapi-secrets.yaml",
					},
				},
				Crowdsec: &csconfig.CrowdsecServiceCfg{
					AcquisitionFilePath: "./tests/acquis.yaml",
					SimulationFilePath:  "./tests/simulation.yaml",
				},
			},
			expected: &csconfig.CrowdsecServiceCfg{
				Enable:               types.BoolPtr(true),
				AcquisitionDirPath:   "",
				AcquisitionFilePath:  acquisFullPath,
				ConfigDir:            configDirFullPath,
				DataDir:              dataFullPath,
				HubDir:               hubFullPath,
				HubIndexFile:         hubIndexFileFullPath,
				BucketsRoutinesCount: 1,
				ParserRoutinesCount:  1,
				OutputRoutinesCount:  1,
				AcquisitionFiles:     []string{acquisFullPath},
				SimulationFilePath:   "./tests/simulation.yaml",
				SimulationConfig: &csconfig.SimulationConfig{
					Simulation: &falseBoolPtr,
				},
			},
		},
		{
			name: "basic valid configuration with acquisition dir",
			Input: &csconfig.Config{
				ConfigPaths: &csconfig.ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &csconfig.APICfg{
					Client: &csconfig.LocalApiClientCfg{
						CredentialsFilePath: "./tests/lapi-secrets.yaml",
					},
				},
				Crowdsec: &csconfig.CrowdsecServiceCfg{
					AcquisitionFilePath: "./tests/acquis.yaml",
					AcquisitionDirPath:  "./tests/acquis/",
					SimulationFilePath:  "./tests/simulation.yaml",
				},
			},
			expected: &csconfig.CrowdsecServiceCfg{
				Enable:               types.BoolPtr(true),
				AcquisitionDirPath:   acquisDirFullPath,
				AcquisitionFilePath:  acquisFullPath,
				ConfigDir:            configDirFullPath,
				HubIndexFile:         hubIndexFileFullPath,
				DataDir:              dataFullPath,
				HubDir:               hubFullPath,
				BucketsRoutinesCount: 1,
				ParserRoutinesCount:  1,
				OutputRoutinesCount:  1,
				AcquisitionFiles:     []string{acquisFullPath, acquisInDirFullPath},
				SimulationFilePath:   "./tests/simulation.yaml",
				SimulationConfig: &csconfig.SimulationConfig{
					Simulation: &falseBoolPtr,
				},
			},
		},
		{
			name: "no acquisition file and dir",
			Input: &csconfig.Config{
				ConfigPaths: &csconfig.ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &csconfig.APICfg{
					Client: &csconfig.LocalApiClientCfg{
						CredentialsFilePath: "./tests/lapi-secrets.yaml",
					},
				},
				Crowdsec: &csconfig.CrowdsecServiceCfg{},
			},
			expected: &csconfig.CrowdsecServiceCfg{
				Enable:               types.BoolPtr(true),
				BucketsRoutinesCount: 1,
				ParserRoutinesCount:  1,
				OutputRoutinesCount:  1,
				ConfigDir:            configDirFullPath,
				HubIndexFile:         hubIndexFileFullPath,
				DataDir:              dataFullPath,
				HubDir:               hubFullPath,
				SimulationConfig: &csconfig.SimulationConfig{
					Simulation: &falseBoolPtr,
				},
			},
		},
		{
			name: "non existing acquisition file",
			Input: &csconfig.Config{
				ConfigPaths: &csconfig.ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
				API: &csconfig.APICfg{
					Client: &csconfig.LocalApiClientCfg{
						CredentialsFilePath: "./tests/lapi-secrets.yaml",
					},
				},
				Crowdsec: &csconfig.CrowdsecServiceCfg{
					AcquisitionFilePath: "./tests/acquis_not_exist.yaml",
				},
			},
			expectedErr: "stat ./tests/acquis_not_exist.yaml: no such file or directory",
		},
		{
			name: "agent disabled",
			Input: &csconfig.Config{
				ConfigPaths: &csconfig.ConfigurationPaths{
					ConfigDir: "./tests",
					DataDir:   "./data",
					HubDir:    "./hub",
				},
			},
			expected: nil,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadCrowdsec()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedErr != "" {
				return
			}

			require.Equal(t, tc.expected, tc.Input.Crowdsec)
		})
	}
}
