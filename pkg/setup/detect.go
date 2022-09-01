package setup

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"

	"github.com/Masterminds/semver"
	"github.com/antonmedv/expr"
	"github.com/blackfireio/osinfo"
	"github.com/shirou/gopsutil/v3/process"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// ExecCommand can be replaced with a mock during tests.
var ExecCommand = exec.Command

// AcquisSupported contains the recommended acquisition options for a service.
type AcquisSupported struct {
	Labels           map[string]string `yaml:"labels,omitempty"`
	LogFiles         []string          `yaml:"log_files,omitempty"`
	JournalCTLFilter []string          `yaml:"journalctl_filter,omitempty"`
}

// AcquisDetected is generated for each service according to the content of AcquisSupported.
type AcquisDetected struct {
	Labels           map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	LogFiles         []string          `json:"log_files,omitempty" yaml:"log_files,omitempty"`
	JournalCTLFilter []string          `json:"journalctl_filter,omitempty" yaml:"journalctl_filter,omitempty"`
}

// SetupItem describes the collection and recommended acquisition options for a detected service.
type SetupItem struct {
	DetectedService string          `json:"detected_service" yaml:"detected_service"`
	Collection      string          `json:"collection,omitempty" yaml:"collection,omitempty"`
	Acquis          *AcquisDetected `json:"acquis,omitempty" yaml:"acquis,omitempty"`
}

// SetupEnvelope is a container for a list of SetupItem objects, allowing for future extensions.
type SetupEnvelope struct {
	Setup []SetupItem `json:"setup":"required"`
}

func readDetectConfig(file string) (DetectConfig, error) {
	var dc DetectConfig

	yamlBytes, err := os.ReadFile(file)
	if err != nil {
		return DetectConfig{}, fmt.Errorf("while reading file: %w", err)
	}

	dec := yaml.NewDecoder(bytes.NewBuffer(yamlBytes))
	dec.KnownFields(true)

	if err = dec.Decode(&dc); err != nil {
		return DetectConfig{}, fmt.Errorf("while parsing %s: %w", file, err)
	}

	switch dc.Version {
	case "":
		return DetectConfig{}, fmt.Errorf("missing version tag (must be 1.0)")
	case "1.0":
		// all is well
	default:
		return DetectConfig{}, fmt.Errorf("unsupported version tag '%s' (must be 1.0)", dc.Version)
	}

	return dc, nil
}

// Service describes the rules for detecting a service and its recommended collection + acquis options.
type Service struct {
	When       []string         `yaml:"when"`
	Collection string           `yaml:"collection"`
	Acquis     *AcquisSupported `yaml:"acquis,omitempty"`
}

// DetectConfig is the container of all detection rules (detect.yaml).
type DetectConfig struct {
	Version  string             `yaml:"version"`
	Services map[string]Service `yaml:"services"`
}

// ExprState keeps a global state for the duration of the service detection (cache etc.)
type ExprState struct {
	unitsSearched map[string]bool
	// slice of unit names that we want to force-detect
	forcedUnits []string
	// cache
	installedUnits map[string]bool

	// true if the list of running processes has already been retrieved, we can
	// avoid getting it a second time.
	processesSearched map[string]bool
	// slice of process names that we want to force-detect
	forcedProcesses []string
	// cache
	runningProcesses map[string]bool
}

// ExprServiceState keep a local state during the detection of a single service. It is reset before each service rules' evaluation.
type ExprServiceState struct {
	detectedUnits []string
}

// ExprOS contains the detected (or forced) OS fields available to the rule engine.
type ExprOS struct {
	Family     string
	ID         string
	RawVersion string
}

// This is not required with Masterminds/semver
/*
// normalizeVersion strips leading zeroes from each part, to allow comparison of ubuntu-like versions.
func normalizeVersion(version string) string {
	// if it doesn't match a version string, return unchanged
	if ok := regexp.MustCompile(`^(\d+)(\.\d+)?(\.\d+)?$`).MatchString(version); !ok {
		// definitely not an ubuntu-like version, return unchanged
		return version
	}

	ret := []rune{}

	var cur rune

	trim := true
	for _, next := range version + "." {
		if trim && cur == '0' && next != '.' {
			cur = next

			continue
		}

		if cur != 0 {
			ret = append(ret, cur)
		}

		trim = (cur == '.' || cur == 0)
		cur = next
	}

	return string(ret)
}
*/

// VersionCheck returns true if the version of the OS matches the given constraint
func (os ExprOS) VersionCheck(constraint string) (bool, error) {
	v, err := semver.NewVersion(os.RawVersion)
	if err != nil {
		return false, err
	}

	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false, err
	}

	return c.Check(v), nil
}

// VersionAtLeast returns true if the version of the OS is at least the given version.
func (os ExprOS) VersionAtLeast(constraint string) (bool, error) {
	return os.VersionCheck(">=" + constraint)
}

// VersionIsLower returns true if the version of the OS is lower than the given version.
func (os ExprOS) VersionIsLower(version string) (bool, error) {
	result, err := os.VersionAtLeast(version)
	if err != nil {
		return false, err
	}
	return !result, nil
}

// ExprEnvironment is used to expose functions and values to to the rule engine.
// It can cache the results of service detection commands, like systemctl etc.
type ExprEnvironment struct {
	OS ExprOS

	_serviceState *ExprServiceState
	_state        *ExprState
}

// NewExprEnvironment creates an environment object for the rule engine.
func NewExprEnvironment(forcedUnits []string, forcedProcesses []string, os ExprOS) ExprEnvironment {
	return ExprEnvironment{
		_state: &ExprState{
			unitsSearched:  make(map[string]bool),
			forcedUnits:    forcedUnits,
			installedUnits: make(map[string]bool),

			processesSearched: make(map[string]bool),
			forcedProcesses:   forcedProcesses,
			runningProcesses:  make(map[string]bool),
		},
		_serviceState: &ExprServiceState{},
		OS:            os,
	}
}

// PathExists returns true if the given path exists.
func (e ExprEnvironment) PathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// UnitFound returns true if the unit is listed in the systemctl output.
// Whether a disabled or failed unit is considered found or not, depends on the
// systemctl parameters used.
func (e ExprEnvironment) UnitFound(unitName string) (bool, error) {
	// fill initial caches
	if len(e._state.unitsSearched) == 0 {
		units, err := systemdUnitList()
		if err != nil {
			return false, err
		}

		for _, name := range units {
			e._state.installedUnits[name] = true
		}

		for _, name := range e._state.forcedUnits {
			e._state.installedUnits[name] = true
		}
	}

	e._state.unitsSearched[unitName] = true
	if e._state.installedUnits[unitName] {
		e._serviceState.detectedUnits = append(e._serviceState.detectedUnits, unitName)

		return true, nil
	}

	return false, nil
}

// ProcessRunning returns true if there is a running process with the given name.
func (e ExprEnvironment) ProcessRunning(processName string) (bool, error) {
	if len(e._state.processesSearched) == 0 {
		procs, err := process.Processes()
		if err != nil {
			return false, fmt.Errorf("while looking up running processes: %w", err)
		}

		for _, p := range procs {
			name, err := p.Name()
			if err != nil {
				return false, fmt.Errorf("while looking up running processes: %w", err)
			}

			e._state.runningProcesses[name] = true
		}

		for _, name := range e._state.forcedProcesses {
			e._state.runningProcesses[name] = true
		}
	}

	e._state.processesSearched[processName] = true

	return e._state.runningProcesses[processName], nil
}

// applyRules checks if the 'when' expressions are true and returns a Service struct,
// augmented with default values and anything that might be useful later on
//
// All expressions are evaluated (no short-circuit) because we want to know if there are errors.
func applyRules(svc Service, env ExprEnvironment) (Service, bool, error) {
	newsvc := svc
	svcok := true
	env._serviceState = &ExprServiceState{}

	for _, rule := range svc.When {
		out, err := expr.Eval(rule, env)
		log.Tracef("  Rule '%s' -> %t, %v", rule, out, err)

		if err != nil {
			return Service{}, false, fmt.Errorf("rule '%s': %w", rule, err)
		}

		outbool, ok := out.(bool)
		if !ok {
			return Service{}, false, fmt.Errorf("rule '%s': type must be a boolean", rule)
		}

		svcok = svcok && outbool
	}

	if newsvc.Acquis == nil || (newsvc.Acquis.LogFiles == nil && newsvc.Acquis.JournalCTLFilter == nil) {
		for _, unitName := range env._serviceState.detectedUnits {
			if newsvc.Acquis == nil {
				newsvc.Acquis = &AcquisSupported{}
			}
			// if there is reference to more than one unit in the rules, we use the first one
			newsvc.Acquis.JournalCTLFilter = []string{fmt.Sprintf(`_SYSTEMD_UNIT=%s`, unitName)}
			break //nolint  // we want to exit after one iteration
		}
	}

	return newsvc, svcok, nil
}

// filterWithRules decorates a DetectConfig map by filtering according to the when: clauses,
// and applying default values or whatever useful to the Service items.
func filterWithRules(dc DetectConfig, env ExprEnvironment) (map[string]Service, error) {
	ret := make(map[string]Service)

	for name := range dc.Services {
		//
		// an empty list of when: clauses defaults to true, if we want
		// to change this behavior, the place is here.
		// if len(svc.When) == 0 {
		// 	log.Warningf("empty 'when' clause: %+v", svc)
		// }
		//
		log.Trace("Evaluating rules for: ", name)

		svc, ok, err := applyRules(dc.Services[name], env)
		if err != nil {
			return nil, fmt.Errorf("while looking for service %s: %w", name, err)
		}

		if !ok {
			log.Tracef("  Skipping %s", name)

			continue
		}

		log.Tracef("  Detected %s", name)

		ret[name] = svc
	}

	return ret, nil
}

// return units that have been forced but not searched yet.
func (e ExprEnvironment) unsearchedUnits() []string {
	ret := []string{}

	for _, unit := range e._state.forcedUnits {
		if !e._state.unitsSearched[unit] {
			ret = append(ret, unit)
		}
	}

	return ret
}

// return processes that have been forced but not searched yet.
func (e ExprEnvironment) unsearchedProcesses() []string {
	ret := []string{}

	for _, proc := range e._state.forcedProcesses {
		if !e._state.processesSearched[proc] {
			ret = append(ret, proc)
		}
	}

	return ret
}

// checkConsumedForcedItems checks if all the "forced" options (units or processes) have been evaluated during the service detection.
func checkConsumedForcedItems(e ExprEnvironment) error {
	unconsumed := e.unsearchedUnits()

	unitMsg := ""
	if len(unconsumed) > 0 {
		unitMsg = fmt.Sprintf("unit(s) forced but not supported: %v", unconsumed)
	}

	unconsumed = e.unsearchedProcesses()

	procsMsg := ""
	if len(unconsumed) > 0 {
		procsMsg = fmt.Sprintf("process(es) forced but not supported: %v", unconsumed)
	}

	join := ""
	if unitMsg != "" && procsMsg != "" {
		join = "; "
	}

	if unitMsg != "" || procsMsg != "" {
		return fmt.Errorf("%s%s%s", unitMsg, join, procsMsg)
	}

	return nil
}

// DetectOptions contains parameters for the Detect function.
type DetectOptions struct {
	ForcedUnits     []string
	ForcedProcesses []string
	ForcedOS        ExprOS
	SkipServices    []string
}

// Detect is the function to call to detect services from a given
// configuration. It outputs a setup file that can be used as input to "cscli
// setup install-collections" or "cscli setup generate-acquis".
func Detect(serviceDetectionFile string, opts DetectOptions) (SetupEnvelope, error) {
	ret := SetupEnvelope{}

	log.Tracef("Reading detection rules: %s", serviceDetectionFile)

	sc, err := readDetectConfig(serviceDetectionFile)
	if err != nil {
		return ret, err
	}

	os := opts.ForcedOS
	if os == (ExprOS{}) {
		osfull, err := osinfo.GetOSInfo()
		if err != nil {
			return ret, fmt.Errorf("detecting OS: %w", err)
		}

		log.Tracef("Detected OS - %+v", *osfull)

		os = ExprOS{
			Family:     osfull.Family,
			ID:         osfull.ID,
			RawVersion: osfull.Version,
		}
	} else {
		log.Tracef("Forced OS - %+v", os)
	}

	if len(opts.ForcedUnits) > 0 {
		log.Tracef("Forced units - %v", opts.ForcedUnits)
	}

	if len(opts.ForcedProcesses) > 0 {
		log.Tracef("Forced processes - %v", opts.ForcedProcesses)
	}

	env := NewExprEnvironment(opts.ForcedUnits, opts.ForcedProcesses, os)

	detected, err := filterWithRules(sc, env)
	if err != nil {
		return ret, err
	}

	if err = checkConsumedForcedItems(env); err != nil {
		return ret, err
	}

	// remove services the user asked to ignore
	for _, name := range opts.SkipServices {
		delete(detected, name)
	}

	// sort the keys (service names) to have them in a predictable
	// order in the final output

	keys := make([]string, 0)
	for k := range detected {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, name := range keys {
		var acquis *AcquisDetected

		svc := detected[name]
		if svc.Acquis != nil {
			if svc.Acquis.Labels["type"] == "" {
				return SetupEnvelope{}, fmt.Errorf("missing type label for service %s", name)
			}
			acquis = &AcquisDetected{
				Labels:           svc.Acquis.Labels,
				LogFiles:         svc.Acquis.LogFiles,
				JournalCTLFilter: svc.Acquis.JournalCTLFilter,
			}
		}

		ret.Setup = append(ret.Setup, SetupItem{
			DetectedService: name,
			Collection:      svc.Collection,
			Acquis:          acquis,
		})
	}

	return ret, nil
}

// ListSupported parses the configuration file and outputs a list of the supported services.
func ListSupported(serviceDetectionFile string) ([]string, error) {
	dc, err := readDetectConfig(serviceDetectionFile)
	if err != nil {
		return nil, err
	}

	keys := make([]string, 0)
	for k := range dc.Services {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys, nil
}
