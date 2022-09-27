package csconfig

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/crowdsecurity/crowdsec/pkg/cstest"
)

func TestSimulationLoading(t *testing.T) {
	testXXFullPath, err := filepath.Abs("./tests/xxx.yaml")
	if err != nil {
		panic(err)
	}

	badYamlFullPath, err := filepath.Abs("./tests/config.yaml")
	if err != nil {
		panic(err)
	}

	noSuchFileMsg := func() string {
		if runtime.GOOS == "windows" {
			return "The system cannot find the file specified."
		}
		return "no such file or directory"
	}

	tests := []struct {
		name           string
		Input          *Config
		expectedResult *SimulationConfig
		expectedErr    string
	}{
		{
			name: "basic valid simulation",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./tests/simulation.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
				Cscli:    &CscliCfg{},
			},
			expectedResult: &SimulationConfig{Simulation: new(bool)},
		},
		{
			name: "basic nil config",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
		},
		{
			name: "basic bad file content",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./tests/config.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			expectedErr: fmt.Sprintf("while unmarshaling simulation file '%s' : yaml: unmarshal errors", badYamlFullPath),
		},
		{
			name: "basic bad file content",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./tests/config.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			expectedErr: fmt.Sprintf("while unmarshaling simulation file '%s' : yaml: unmarshal errors", badYamlFullPath),
		},
		{
			name: "basic bad file name",
			Input: &Config{
				ConfigPaths: &ConfigurationPaths{
					SimulationFilePath: "./tests/xxx.yaml",
					DataDir:            "./data",
				},
				Crowdsec: &CrowdsecServiceCfg{},
			},
			expectedErr: fmt.Sprintf("while reading yaml file: open %s: %s", testXXFullPath, noSuchFileMsg()),
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadSimulation()
			cstest.RequireErrorContains(t, err, tc.expectedErr)
			require.Equal(t, tc.expectedResult, tc.Input.Crowdsec.SimulationConfig)
		})
	}
}

func TestIsSimulated(t *testing.T) {
	simCfgOff := &SimulationConfig{
		Simulation: new(bool),
		Exclusions: []string{"test"},
	}

	simCfgOn := &SimulationConfig{
		Simulation: new(bool),
		Exclusions: []string{"test"},
	}
	*simCfgOn.Simulation = true

	tests := []struct {
		name             string
		SimulationConfig *SimulationConfig
		Input            string
		expectedResult   bool
	}{
		{
			name:             "No simulation except (in exclusion)",
			SimulationConfig: simCfgOff,
			Input:            "test",
			expectedResult:   true,
		},
		{
			name:             "All simulation (not in exclusion)",
			SimulationConfig: simCfgOn,
			Input:            "toto",
			expectedResult:   true,
		},
		{
			name:             "All simulation (in exclusion)",
			SimulationConfig: simCfgOn,
			Input:            "test",
			expectedResult:   false,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			IsSimulated := tc.SimulationConfig.IsSimulated(tc.Input)
			require.Equal(t, tc.expectedResult, IsSimulated)
		})
	}
}
