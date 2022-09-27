package csconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/cstest"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestLoadLocalApiClientCfg(t *testing.T) {
	True := true
	tests := []struct {
		name           string
		Input          *LocalApiClientCfg
		expectedResult *ApiCredentialsCfg
		expectedErr    string
	}{
		{
			name: "basic valid configuration",
			Input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/lapi-secrets.yaml",
			},
			expectedResult: &ApiCredentialsCfg{
				URL:      "http://localhost:8080/",
				Login:    "test",
				Password: "testpassword",
			},
		},
		{
			name: "invalid configuration",
			Input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/bad_lapi-secrets.yaml",
			},
			expectedResult: &ApiCredentialsCfg{},
		},
		{
			name: "invalid configuration filepath",
			Input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/nonexist_lapi-secrets.yaml",
			},
			expectedResult: nil,
		},
		{
			name: "valid configuration with insecure skip verify",
			Input: &LocalApiClientCfg{
				CredentialsFilePath: "./tests/lapi-secrets.yaml",
				InsecureSkipVerify:  &True,
			},
			expectedResult: &ApiCredentialsCfg{
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
		Input          *OnlineApiClientCfg
		expectedResult *ApiCredentialsCfg
		expectedErr    string
	}{
		{
			name: "basic valid configuration",
			Input: &OnlineApiClientCfg{
				CredentialsFilePath: "./tests/online-api-secrets.yaml",
			},
			expectedResult: &ApiCredentialsCfg{
				URL:      "http://crowdsec.api",
				Login:    "test",
				Password: "testpassword",
			},
		},
		{
			name: "invalid configuration",
			Input: &OnlineApiClientCfg{
				CredentialsFilePath: "./tests/bad_lapi-secrets.yaml",
			},
			expectedResult: &ApiCredentialsCfg{},
			expectedErr: "failed unmarshaling api server credentials",
		},
		{
			name: "missing field configuration",
			Input: &OnlineApiClientCfg{
				CredentialsFilePath: "./tests/bad_online-api-secrets.yaml",
			},
			expectedResult: nil,
		},
		{
			name: "invalid configuration filepath",
			Input: &OnlineApiClientCfg{
				CredentialsFilePath: "./tests/nonexist_online-api-secrets.yaml",
			},
			expectedResult: &ApiCredentialsCfg{},
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
	tmpLAPI := &LocalApiServerCfg{
		ProfilesPath: "./tests/profiles.yaml",
	}
	if err := tmpLAPI.LoadProfiles(); err != nil {
		t.Fatalf("loading tmp profiles: %+v", err)
	}

	LogDirFullPath, err := filepath.Abs("./tests")
	require.NoError(t, err)

	config := &Config{}
	fcontent, err := os.ReadFile("./tests/config.yaml")
	require.NoError(t, err)

	configData := os.ExpandEnv(string(fcontent))
	err = yaml.UnmarshalStrict([]byte(configData), &config)
	require.NoError(t, err)

	tests := []struct {
		name           string
		Input          *Config
		expectedResult *LocalApiServerCfg
		expectedErr    string
	}{
		{
			name: "basic valid configuration",
			Input: &Config{
				Self: []byte(configData),
				API: &APICfg{
					Server: &LocalApiServerCfg{
						ListenURI: "http://crowdsec.api",
						OnlineClient: &OnlineApiClientCfg{
							CredentialsFilePath: "./tests/online-api-secrets.yaml",
						},
						ProfilesPath: "./tests/profiles.yaml",
					},
				},
				DbConfig: &DatabaseCfg{
					Type:   "sqlite",
					DbPath: "./tests/test.db",
				},
				Common: &CommonCfg{
					LogDir:   "./tests/",
					LogMedia: "stdout",
				},
				DisableAPI: false,
			},
			expectedResult: &LocalApiServerCfg{
				Enable:    types.BoolPtr(true),
				ListenURI: "http://crowdsec.api",
				TLS:       nil,
				DbConfig: &DatabaseCfg{
					DbPath:       "./tests/test.db",
					Type:         "sqlite",
					MaxOpenConns: types.IntPtr(DEFAULT_MAX_OPEN_CONNS),
				},
				ConsoleConfigPath: DefaultConfigPath("console.yaml"),
				ConsoleConfig: &ConsoleConfig{
					ShareManualDecisions:  types.BoolPtr(false),
					ShareTaintedScenarios: types.BoolPtr(true),
					ShareCustomScenarios:  types.BoolPtr(true),
				},
				LogDir:   LogDirFullPath,
				LogMedia: "stdout",
				OnlineClient: &OnlineApiClientCfg{
					CredentialsFilePath: "./tests/online-api-secrets.yaml",
					Credentials: &ApiCredentialsCfg{
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
			Input: &Config{
				Self: []byte(configData),
				API: &APICfg{
					Server: &LocalApiServerCfg{},
				},
				Common: &CommonCfg{
					LogDir:   "./tests/",
					LogMedia: "stdout",
				},
				DisableAPI: false,
			},
			expectedResult: &LocalApiServerCfg{
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
