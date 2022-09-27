package csconfig_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestLoadLocalApiClientCfg(t *testing.T) {
	True := true
	tests := []struct {
		name           string
		Input          *csconfig.LocalApiClientCfg
		expectedResult *csconfig.ApiCredentialsCfg
		expectedErr    string
	}{
		{
			name: "basic valid configuration",
			Input: &csconfig.LocalApiClientCfg{
				CredentialsFilePath: "./tests/lapi-secrets.yaml",
			},
			expectedResult: &csconfig.ApiCredentialsCfg{
				URL:      "http://localhost:8080/",
				Login:    "test",
				Password: "testpassword",
			},
		},
		{
			name: "invalid configuration",
			Input: &csconfig.LocalApiClientCfg{
				CredentialsFilePath: "./tests/bad_lapi-secrets.yaml",
			},
			expectedErr: "field unknown_key not found in type csconfig.ApiCredentialsCfg",
		},
		{
			name: "invalid configuration filepath",
			Input: &csconfig.LocalApiClientCfg{
				CredentialsFilePath: "./tests/nonexist_lapi-secrets.yaml",
			},
			expectedErr: "no such file or directory",
		},
		{
			name: "valid configuration with insecure skip verify",
			Input: &csconfig.LocalApiClientCfg{
				CredentialsFilePath: "./tests/lapi-secrets.yaml",
				InsecureSkipVerify:  &True,
			},
			expectedResult: &csconfig.ApiCredentialsCfg{
				URL:      "http://localhost:8080/",
				Login:    "test",
				Password: "testpassword",
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.Load()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedErr != "" {
				return
			}

			require.Equal(t, tc.expectedResult, tc.Input.Credentials)
		})

	}
}

func TestLoadOnlineApiClientCfg(t *testing.T) {
	tests := []struct {
		name           string
		Input          *csconfig.OnlineApiClientCfg
		expectedResult *csconfig.ApiCredentialsCfg
		expectedErr    string
	}{
		{
			name: "basic valid configuration",
			Input: &csconfig.OnlineApiClientCfg{
				CredentialsFilePath: "./tests/online-api-secrets.yaml",
			},
			expectedResult: &csconfig.ApiCredentialsCfg{
				URL:      "http://crowdsec.api",
				Login:    "test",
				Password: "testpassword",
			},
		},
		{
			name: "invalid configuration",
			Input: &csconfig.OnlineApiClientCfg{
				CredentialsFilePath: "./tests/bad_lapi-secrets.yaml",
			},
			expectedResult: &csconfig.ApiCredentialsCfg{},
			expectedErr: "failed unmarshaling api server credentials",
		},
		{
			name: "missing field configuration",
			Input: &csconfig.OnlineApiClientCfg{
				CredentialsFilePath: "./tests/bad_online-api-secrets.yaml",
			},
			expectedResult: nil,
		},
		{
			name: "invalid configuration filepath",
			Input: &csconfig.OnlineApiClientCfg{
				CredentialsFilePath: "./tests/nonexist_online-api-secrets.yaml",
			},
			expectedResult: &csconfig.ApiCredentialsCfg{},
			expectedErr: "failed to read api server credentials",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.Load()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedErr != "" {
				return
			}

			require.Equal(t, tc.expectedResult, tc.Input.Credentials)
		})
	}
}

func TestLoadAPIServer(t *testing.T) {
	tmpLAPI := &csconfig.LocalApiServerCfg{
		ProfilesPath: "./tests/profiles.yaml",
	}
	if err := tmpLAPI.LoadProfiles(); err != nil {
		t.Fatalf("loading tmp profiles: %+v", err)
	}

	LogDirFullPath, err := filepath.Abs("./tests")
	require.NoError(t, err)

	config := &csconfig.Config{}
	fcontent, err := os.ReadFile("./tests/config.yaml")
	require.NoError(t, err)

	configData := os.ExpandEnv(string(fcontent))
	err = yaml.UnmarshalStrict([]byte(configData), &config)
	require.NoError(t, err)

	tests := []struct {
		name           string
		Input          *csconfig.Config
		expectedResult *csconfig.LocalApiServerCfg
		expectedErr    string
	}{
		{
			name: "basic valid configuration",
			Input: &csconfig.Config{
				Self: []byte(configData),
				API: &csconfig.APICfg{
					Server: &csconfig.LocalApiServerCfg{
						ListenURI: "http://crowdsec.api",
						OnlineClient: &csconfig.OnlineApiClientCfg{
							CredentialsFilePath: "./tests/online-api-secrets.yaml",
						},
						ProfilesPath: "./tests/profiles.yaml",
					},
				},
				DbConfig: &csconfig.DatabaseCfg{
					Type:   "sqlite",
					DbPath: "./tests/test.db",
				},
				Common: &csconfig.CommonCfg{
					LogDir:   "./tests/",
					LogMedia: "stdout",
				},
				DisableAPI: false,
			},
			expectedResult: &csconfig.LocalApiServerCfg{
				Enable:    types.BoolPtr(true),
				ListenURI: "http://crowdsec.api",
				TLS:       nil,
				DbConfig: &csconfig.DatabaseCfg{
					DbPath:       "./tests/test.db",
					Type:         "sqlite",
					MaxOpenConns: types.IntPtr(csconfig.DEFAULT_MAX_OPEN_CONNS),
				},
				ConsoleConfigPath: csconfig.DefaultConfigPath("console.yaml"),
				ConsoleConfig: &csconfig.ConsoleConfig{
					ShareManualDecisions:  types.BoolPtr(false),
					ShareTaintedScenarios: types.BoolPtr(true),
					ShareCustomScenarios:  types.BoolPtr(true),
				},
				LogDir:   LogDirFullPath,
				LogMedia: "stdout",
				OnlineClient: &csconfig.OnlineApiClientCfg{
					CredentialsFilePath: "./tests/online-api-secrets.yaml",
					Credentials: &csconfig.ApiCredentialsCfg{
						URL:      "http://crowdsec.api",
						Login:    "test",
						Password: "testpassword",
					},
				},
				Profiles:               tmpLAPI.Profiles,
				ProfilesPath:           "./tests/profiles.yaml",
				UseForwardedForHeaders: false,
			},
			expectedErr: "",
		},
		{
			name: "basic invalid configuration",
			Input: &csconfig.Config{
				Self: []byte(configData),
				API: &csconfig.APICfg{
					Server: &csconfig.LocalApiServerCfg{},
				},
				Common: &csconfig.CommonCfg{
					LogDir:   "./tests/",
					LogMedia: "stdout",
				},
				DisableAPI: false,
			},
			expectedResult: &csconfig.LocalApiServerCfg{
				Enable:   types.BoolPtr(true),
				LogDir:   LogDirFullPath,
				LogMedia: "stdout",
			},
			expectedErr: "while loading profiles for LAPI",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			err := tc.Input.LoadAPIServer()
			cstest.RequireErrorContains(t, err, tc.expectedErr)

			if tc.expectedErr != "" {
				return
			}

			require.Equal(t, tc.expectedResult, tc.Input.API.Server)
		})
	}
}
