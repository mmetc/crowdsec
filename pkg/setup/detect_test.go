package setup_test

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/setup"
	"github.com/lithammer/dedent"
	"github.com/stretchr/testify/require"
)

var fakeSystemctlOutput = `UNIT FILE                                 STATE    VENDOR PRESET
crowdsec-setup-detect.service            enabled  enabled
apache2.service                           enabled  enabled
apparmor.service                          enabled  enabled
apport.service                            enabled  enabled
atop.service                              enabled  enabled
atopacct.service                          enabled  enabled
finalrd.service                           enabled  enabled
fwupd-refresh.service                     enabled  enabled
fwupd.service                             enabled  enabled

9 unit files listed.`

func fakeExecCommandNotFound(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestSetupHelperProcess", "--", command}
	cs = append(cs, args...)
	cmd := exec.Command("this-command-does-not-exist", cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

	return cmd
}

func fakeExecCommand(command string, args ...string) *exec.Cmd {
	cs := []string{"-test.run=TestSetupHelperProcess", "--", command}
	cs = append(cs, args...)
	//nolint:gosec
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}

	return cmd
}

func TestSetupHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	fmt.Fprint(os.Stdout, fakeSystemctlOutput)
	os.Exit(0)
}

func requireErrorContains(t *testing.T, err error, expectedErr string) {
	t.Helper()

	if expectedErr != "" {
		require.ErrorContains(t, err, expectedErr)

		return
	}

	require.NoError(t, err)
}

func tempYAML(t *testing.T, content string) string {
	t.Helper()
	require := require.New(t)
	file, err := os.CreateTemp("", "")
	require.NoError(err)

	_, err = file.WriteString(dedent.Dedent(content))
	require.NoError(err)

	err = file.Close()
	require.NoError(err)

	return file.Name()
}

func TestPathExists(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		expected bool
	}{
		{"/boot", true},
		{"/tmp", true},
		{"/this-should-not-exist", false},
	}

	for _, tc := range tests {
		tc := tc
		env := setup.NewExprEnvironment([]string{}, []string{}, setup.ExprOS{})
		t.Run(tc.path, func(t *testing.T) {
			t.Parallel()
			actual := env.PathExists(tc.path)
			require.Equal(t, tc.expected, actual)
		})
	}
}

func TestVersionCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version     string
		constraint  string
		expected    bool
		expectedErr string
	}{
		{"1", "=1", true, ""},
		{"1", "!=1", false, ""},
		{"1", "<=1", true, ""},
		{"1", ">1", false, ""},
		{"1", ">=1", true, ""},
		{"1.0", "<1.0", false, ""},
		{"1", "<1", true, ""},       // XXX why?
		{"1.3.5", "1.3", false, ""}, // XXX ok?
		{"1.0", "<1.0", false, ""},
		{"1.0", "<=1.0", true, ""},
		{"2", ">1, <3", true, ""},
		{"2", "<=2, >=2.2", false, ""},
		{"2.3", "~2", true, ""},
		{"2.3", "=2", true, ""},
		{"1.1.1", "=1.1", false, ""},
		{"1.1.1", "1.1", false, ""},
		{"1.1", "!=1.1.1", true, ""},
		{"1.1", "~1.1.1", false, ""},
		{"1.1.1", "~1.1", true, ""},
		{"1.1.3", "~1.1", true, ""},
		{"19.04", "<19.10", true, ""},
		{"19.04", ">=19.10", false, ""},
		{"19.04", "=19.4", true, ""},
		{"19.04", "~19.4", true, ""},
		{"1.2.3", "~1.2", true, ""},
		{"1.2.3", "!=1.2", true, ""},
		{"1.2.3", "1.1.1 - 1.3.4", true, ""},
		{"1.3.5", "1.1.1 - 1.3.4", false, ""},
		{"1.3.5", "=1", true, ""},
		{"1.3.5", "1", true, ""},
	}

	for _, tc := range tests {
		tc := tc
		e := setup.ExprOS{RawVersion: tc.version}
		t.Run(fmt.Sprintf("Check(%s,%s)", tc.version, tc.constraint), func(t *testing.T) {
			t.Parallel()
			actual, err := e.VersionCheck(tc.constraint)
			requireErrorContains(t, err, tc.expectedErr)
			require.Equal(t, tc.expected, actual)
		})
	}
}

// This is not required for Masterminds/semver
/*
func TestNormalizeVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version  string
		expected string
	}{
		{"0", "0"},
		{"2", "2"},
		{"3.14", "3.14"},
		{"1.0", "1.0"},
		{"18.04", "18.4"},
		{"0.0.0", "0.0.0"},
		{"18.04.0", "18.4.0"},
		{"18.0004.0", "18.4.0"},
		{"21.04.2", "21.4.2"},
		{"050", "50"},
		{"trololo", "trololo"},
		{"0001.002.03", "1.2.3"},
		{"0001.002.03-trololo", "0001.002.03-trololo"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.version, func(t *testing.T) {
			t.Parallel()
			actual := setup.NormalizeVersion(tc.version)
			require.Equal(t, tc.expected, actual)
		})
	}
}
*/

func TestListSupported(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		yml         string
		expected    []string
		expectedErr string
	}{
		{
			"list configured services",
			`
			version: 1.0
			services:
			  foo:
			  bar:
			  baz:
			`,
			[]string{"foo", "bar", "baz"},
			"",
		},
		{
			"invalid yaml: blah blah",
			"blahblah",
			nil,
			"yaml: unmarshal errors:",
		},
		{
			"invalid yaml: tabs are not allowed",
			`
			version: 1.0
			services:
				foos:
			`,
			nil,
			"yaml: line 4: found character that cannot start any token",
		},
		{
			"invalid yaml: no version",
			"{}",
			nil,
			"missing version tag (must be 1.0)",
		},
		{
			"invalid yaml: bad version",
			"version: 2.0",
			nil,
			"unsupported version tag '2.0' (must be 1.0)",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := tempYAML(t, tc.yml)
			defer os.Remove(f)
			supported, err := setup.ListSupported(f)
			requireErrorContains(t, err, tc.expectedErr)
			require.ElementsMatch(t, tc.expected, supported)
		})
	}
}

func TestApplyRules(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	tests := []struct {
		name        string
		rules       []string
		expectedOk  bool
		expectedErr string
	}{
		{
			"empty list is always true", // XXX or false?
			[]string{},
			true,
			"",
		},
		{
			"simple true expression",
			[]string{"1+1==2"},
			true,
			"",
		},
		{
			"simple false expression",
			[]string{"2+2==5"},
			false,
			"",
		},
		{
			"all expressions are true",
			[]string{"1+2==3", "1!=2"},
			true,
			"",
		},
		{
			"all expressions must be true",
			[]string{"true", "1==3", "1!=2"},
			false,
			"",
		},
		{
			"each expression must be a boolan",
			[]string{"true", "\"notabool\""},
			false,
			"rule '\"notabool\"': type must be a boolean",
		},
		{
			// we keep evaluating expressions to ensure that the
			// file is formally correct, even if it can some time.
			"each expression must be a boolan (no short circuit)",
			[]string{"false", "3"},
			false,
			"rule '3': type must be a boolean",
		},
		{
			"unknown variable",
			[]string{"false", "doesnotexist"},
			false,
			"rule 'doesnotexist': cannot fetch doesnotexist from",
		},
		{
			"unknown expression",
			[]string{"false", "doesnotexist()"},
			false,
			"rule 'doesnotexist()': cannot get \"doesnotexist\" from",
		},
	}

	env := setup.ExprEnvironment{}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := setup.Service{When: tc.rules}
			_, actualOk, err := setup.ApplyRules(svc, env) //nolint:typecheck,nolintlint  // exported only for tests
			requireErrorContains(t, err, tc.expectedErr)
			require.Equal(tc.expectedOk, actualOk)
		})
	}
}

// XXX TODO: TestApplyRules with journalctl default

func TestUnitFound(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	env := setup.NewExprEnvironment([]string{}, []string{}, setup.ExprOS{})

	installed, err := env.UnitFound("crowdsec-setup-detect.service")
	require.NoError(err)

	require.Equal(true, installed)
}

// TODO apply rules to filter a list of Service structs
// func testFilterWithRules(t *testing.T) {
// }

func TestDetectSimpleRule(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	f := tempYAML(t, `
	version: 1.0
	services:
	  good:
	    when:
	      - true
	  bad:
	    when:
	      - false
	  ugly:
	`)
	defer os.Remove(f)

	detected, err := setup.Detect(f, setup.DetectOptions{})
	require.NoError(err)

	expected := []setup.SetupItem{
		{DetectedService: "good"},
		{DetectedService: "ugly"},
	}

	require.ElementsMatch(expected, detected.Setup)
}

func TestDetectUnitError(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommandNotFound

	defer func() { setup.ExecCommand = exec.Command }()

	tests := []struct {
		name        string
		config      string
		expected    setup.SetupEnvelope
		expectedErr string
	}{
		{
			"error is reported if systemctl does not exist",
			`
version: 1.0
services:
  wizard:
    when:
      - UnitFound("crowdsec-setup-detect.service")
    acquis:
      labels:
        type: syslog`,
			setup.SetupEnvelope{},
			`while looking for service wizard: rule 'UnitFound("crowdsec-setup-detect.service")': ` +
				`running systemctl: exec: "this-command-does-not-exist": executable file not found in $PATH`,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := tempYAML(t, tc.config)
			defer os.Remove(f)

			detected, err := setup.Detect(f, setup.DetectOptions{})
			requireErrorContains(t, err, tc.expectedErr)
			require.Equal(tc.expected, detected)
		})
	}
}

func TestDetectUnit(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	tests := []struct {
		name        string
		config      string
		expected    setup.SetupEnvelope
		expectedErr string
	}{
		{
			"detect a single unit, with default log filter",
			`
version: 1.0
services:
  wizard:
    when:
      - UnitFound("crowdsec-setup-detect.service")
    acquis:
      labels:
        type: syslog
  sorcerer:
    when:
      - UnitFound("sorcerer.service")`,
			setup.SetupEnvelope{
				Setup: []setup.SetupItem{
					{
						DetectedService: "wizard",
						Acquis: &setup.AcquisDetected{
							Labels:           map[string]string{"type": "syslog"},
							JournalCTLFilter: []string{"_SYSTEMD_UNIT=crowdsec-setup-detect.service"},
						},
					},
				},
			},
			"",
		},
		{
			"detect a single unit, but type label is missing",
			`
version: 1.0
services:
  wizard:
    when:
      - UnitFound("crowdsec-setup-detect.service")`,
			setup.SetupEnvelope{},
			"missing type label for service wizard",
		},
		{
			"detect unit and pick up acquisistion filter",
			`
version: 1.0
services:
  wizard:
    when:
      - UnitFound("crowdsec-setup-detect.service")
    acquis:
      labels:
        type: syslog
      journalctl_filter:
        - _MY_CUSTOM_FILTER=something`,
			setup.SetupEnvelope{
				Setup: []setup.SetupItem{
					{
						DetectedService: "wizard",
						Acquis: &setup.AcquisDetected{
							Labels:           map[string]string{"type": "syslog"},
							JournalCTLFilter: []string{"_MY_CUSTOM_FILTER=something"},
						},
					},
				},
			},
			"",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := tempYAML(t, tc.config)
			defer os.Remove(f)

			detected, err := setup.Detect(f, setup.DetectOptions{})
			requireErrorContains(t, err, tc.expectedErr)
			require.Equal(tc.expected, detected)
		})
	}
}

func TestDetectForcedUnit(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	f := tempYAML(t, `
	version: 1.0
	services:
	  wizard:
	    when:
	      - UnitFound("crowdsec-setup-forced.service")
	    acquis:
	      labels:
	        type: syslog
	      journalctl_filter:
	        - _SYSTEMD_UNIT=crowdsec-setup-forced.service
	`)
	defer os.Remove(f)

	detected, err := setup.Detect(f, setup.DetectOptions{ForcedUnits: []string{"crowdsec-setup-forced.service"}})
	require.NoError(err)

	expected := setup.SetupEnvelope{
		Setup: []setup.SetupItem{
			{
				DetectedService: "wizard",
				Acquis: &setup.AcquisDetected{
					Labels:           map[string]string{"type": "syslog"},
					JournalCTLFilter: []string{"_SYSTEMD_UNIT=crowdsec-setup-forced.service"},
				},
			},
		},
	}
	require.Equal(expected, detected)
}

func TestDetectForcedProcess(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	f := tempYAML(t, `
	version: 1.0
	services:
	  wizard:
	    when:
	      - ProcessRunning("foobar")
	`)
	defer os.Remove(f)

	detected, err := setup.Detect(f, setup.DetectOptions{ForcedProcesses: []string{"foobar"}})
	require.NoError(err)

	expected := setup.SetupEnvelope{
		Setup: []setup.SetupItem{
			{DetectedService: "wizard"},
		},
	}
	require.Equal(expected, detected)
}

func TestDetectSkipService(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	f := tempYAML(t, `
	version: 1.0
	services:
	  wizard:
	    when:
	      - ProcessRunning("foobar")
	`)
	defer os.Remove(f)

	detected, err := setup.Detect(f, setup.DetectOptions{ForcedProcesses: []string{"foobar"}, SkipServices: []string{"wizard"}})
	require.NoError(err)

	expected := setup.SetupEnvelope{}
	require.Equal(expected, detected)
}

func TestDetectForcedOS(t *testing.T) {
	require := require.New(t)
	setup.ExecCommand = fakeExecCommand

	defer func() { setup.ExecCommand = exec.Command }()

	type test struct {
		name        string
		config      string
		forced      setup.ExprOS
		expected    setup.SetupEnvelope
		expectedErr string
	}

	tests := []test{
		{
			"detect OS - force linux",
			`
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.Family == "linux"`,
			setup.ExprOS{Family: "linux"},
			setup.SetupEnvelope{
				Setup: []setup.SetupItem{
					{DetectedService: "linux"},
				},
			},
			"",
		},
		{
			"detect OS - force windows",
			`
	version: 1.0
	services:
	  windows:
	    when:
	      - OS.Family == "windows"`,
			setup.ExprOS{Family: "windows"},
			setup.SetupEnvelope{
				Setup: []setup.SetupItem{
					{DetectedService: "windows"},
				},
			},
			"",
		},
		{
			"detect OS - ubuntu (no match)",
			`
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.Family == "linux" && OS.ID == "ubuntu"`,
			setup.ExprOS{Family: "linux"},
			setup.SetupEnvelope{},
			"",
		},
		{
			"detect OS - ubuntu (match)",
			`
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.Family == "linux" && OS.ID == "ubuntu"`,
			setup.ExprOS{Family: "linux", ID: "ubuntu"},
			setup.SetupEnvelope{
				Setup: []setup.SetupItem{
					{DetectedService: "linux"},
				},
			},
			"",
		},
		{
			"detect OS - ubuntu (match with version)",
			`
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.Family == "linux" && OS.ID == "ubuntu" && OS.VersionCheck("19.04")`,
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "19.04"},
			setup.SetupEnvelope{
				Setup: []setup.SetupItem{
					{DetectedService: "linux"},
				},
			},
			"",
		},
		{
			"detect OS - ubuntu >= 20.04 (no match: no version detected)",
			`
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.ID == "ubuntu" && OS.VersionCheck(">=20.04")`,
			setup.ExprOS{Family: "linux"},
			setup.SetupEnvelope{},
			"",
		},
		{
			"detect OS - ubuntu >= 20.04 (no match: version is lower)",
			`
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.ID == "ubuntu" && OS.VersionCheck(">=20.04")`,
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "19.10"},
			setup.SetupEnvelope{},
			"",
		},
		{
			"detect OS - ubuntu >= 20.04 (match: same version)",
			`
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.ID == "ubuntu" && OS.VersionCheck(">=20.04")`,
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "20.04"},
			setup.SetupEnvelope{
				Setup: []setup.SetupItem{
					{DetectedService: "linux"},
				},
			},
			"",
		},
		{
			"detect OS - ubuntu >= 20.04 (match: version is higher)",
			`
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.ID == "ubuntu" && OS.VersionCheck(">=20.04")`,
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "22.04"},
			setup.SetupEnvelope{
				Setup: []setup.SetupItem{
					{DetectedService: "linux"},
				},
			},
			"",
		},

		{
			"detect OS - ubuntu < 20.04 (no match: no version detected)",
			`
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.ID == "ubuntu" && OS.VersionCheck("<20.04")`,
			setup.ExprOS{Family: "linux"},
			setup.SetupEnvelope{},
			"",
		},
		{
			"detect OS - ubuntu < 20.04 (no match: version is higher)",
			`
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.ID == "ubuntu" && OS.VersionCheck("<20.04")`,
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "20.10"},
			setup.SetupEnvelope{},
			"",
		},
		{
			"detect OS - ubuntu < 20.04 (no match: same version)",
			`
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.ID == "ubuntu" && OS.VersionCheck("<20.04")`,
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "20.04"},
			setup.SetupEnvelope{},
			"",
		},
		{
			"detect OS - ubuntu < 20.04 (match: version is lower)",
			`
	version: 1.0
	services:
	  linux:
	    when:
	      - OS.ID == "ubuntu"
	      - OS.VersionCheck("<20.04")`,
			setup.ExprOS{Family: "linux", ID: "ubuntu", RawVersion: "19.10"},
			setup.SetupEnvelope{
				Setup: []setup.SetupItem{
					{DetectedService: "linux"},
				},
			},
			"",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := tempYAML(t, tc.config)
			defer os.Remove(f)

			detected, err := setup.Detect(f, setup.DetectOptions{ForcedOS: tc.forced})
			requireErrorContains(t, err, tc.expectedErr)
			require.Equal(tc.expected, detected)
		})
	}
}
