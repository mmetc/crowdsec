package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/setup"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// NewSetupCmd defines the "cscli setup" command.
func NewSetupCmd() *cobra.Command {
	cmdSetup := &cobra.Command{
		Use:               "setup",
		Short:             "Tools to configure crowdsec",
		Long:              "Manage hub configuration and service detection",
		Args:              cobra.MinimumNArgs(0),
		DisableAutoGenTag: true,
	}

	//
	// cscli setup detect
	//
	{
		cmdSetupDetect := &cobra.Command{
			Use:               "detect",
			Short:             "detect running services, generate a setup file",
			DisableAutoGenTag: true,
			RunE:              runSetupDetect,
		}

		defaultServiceDetect := csconfig.DefaultConfigPath("hub", "detect.yaml")

		flags := cmdSetupDetect.Flags()
		flags.String("detect-config", defaultServiceDetect, "path to service detection configuration")
		flags.Bool("list-supported-services", false, "do not detect; only print supported services")
		flags.StringSlice("force-unit", nil, "force detection of a systemd unit (can be repeated)")
		flags.StringSlice("force-process", nil, "force detection of a running process (can be repeated)")
		flags.StringSlice("skip-service", nil, "ignore a service, don't recommend collections/acquis (can be repeated)")
		flags.String("force-os-family", "", "override OS.Family: one of linux, freebsd, windows or darwin")
		flags.String("force-os-id", "", "override OS.ID=[debian | ubuntu | , redhat...]")
		flags.String("force-os-version", "", "override OS.RawVersion (of OS or Linux distribution)")
		flags.Bool("yaml", false, "output yaml, not json")
		cmdSetup.AddCommand(cmdSetupDetect)
	}

	//
	// cscli setup install-collections
	//
	{
		cmdSetupInstallCollections := &cobra.Command{
			Use:               "install-collections [setup_file] [flags]",
			Short:             "install items from a setup file",
			Args:              cobra.ExactArgs(1),
			DisableAutoGenTag: true,
			RunE:              runSetupInstallCollections,
		}

		flags := cmdSetupInstallCollections.Flags()
		flags.Bool("dry-run", false, "don't install anything; print out what would have been")
		cmdSetup.AddCommand(cmdSetupInstallCollections)
	}

	//
	// cscli setup generate-acquis
	//
	{
		cmdSetupGenerateAcquis := &cobra.Command{
			Use:               "generate-acquis [setup_file] [flags]",
			Short:             "generate acquisition config from a setup file",
			Args:              cobra.ExactArgs(1),
			DisableAutoGenTag: true,
			RunE:              runSetupGenerateAcquis,
		}

		flags := cmdSetupGenerateAcquis.Flags()
		flags.String("to-dir", "", "write the acquisition configuration to a directory, in multiple files")
		cmdSetup.AddCommand(cmdSetupGenerateAcquis)
	}

	//
	// cscli setup validate
	//
	{
		cmdSetupValidate := &cobra.Command{
			Use:               "validate [setup_file]",
			Short:             "validate a setup file",
			Args:              cobra.ExactArgs(1),
			DisableAutoGenTag: true,
			RunE:              runSetupValidate,
		}

		cmdSetup.AddCommand(cmdSetupValidate)
	}

	return cmdSetup
}

func runSetupDetect(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	detectConfigFile, err := flags.GetString("detect-config")
	if err != nil {
		return err
	}

	listSupportedServices, err := flags.GetBool("list-supported-services")
	if err != nil {
		return err
	}

	forcedUnits, err := flags.GetStringSlice("force-unit")
	if err != nil {
		return err
	}

	forcedProcesses, err := flags.GetStringSlice("force-process")
	if err != nil {
		return err
	}

	forcedOSFamily, err := flags.GetString("force-os-family")
	if err != nil {
		return err
	}

	forcedOSID, err := flags.GetString("force-os-id")
	if err != nil {
		return err
	}

	forcedOSVersion, err := flags.GetString("force-os-version")
	if err != nil {
		return err
	}

	skipServices, err := flags.GetStringSlice("skip-service")
	if err != nil {
		return err
	}

	outYaml, err := flags.GetBool("yaml")
	if err != nil {
		return err
	}

	if forcedOSFamily == "" && forcedOSID != "" {
		log.Debug("force-os-id is set: force-os-family defaults to 'linux'")
		forcedOSFamily = "linux"
	}

	if listSupportedServices {
		supported, err := setup.ListSupported(detectConfigFile)
		if err != nil {
			return err
		}

		for _, svc := range supported {
			fmt.Println(svc)
		}

		return nil
	}

	opts := setup.DetectOptions{
		ForcedUnits:     forcedUnits,
		ForcedProcesses: forcedProcesses,
		ForcedOS: setup.ExprOS{
			Family:     forcedOSFamily,
			ID:         forcedOSID,
			RawVersion: forcedOSVersion,
		},
		SkipServices: skipServices,
	}

	collectionSetup, err := setup.Detect(detectConfigFile, opts)
	if err != nil {
		return fmt.Errorf("detecting services: %w", err)
	}

	setup, err := setupAsString(collectionSetup, outYaml)
	if err != nil {
		return err
	}
	fmt.Println(setup)

	return nil
}

func setupAsString(cs setup.SetupEnvelope, outYaml bool) (string, error) {
	wrap := func(err error) error {
		return fmt.Errorf("while marshaling setup: %w", err)
	}

	if outYaml {
		indentLevel := 2
		buf := &bytes.Buffer{}
		enc := yaml.NewEncoder(buf)
		enc.SetIndent(indentLevel)

		if err := enc.Encode(cs); err != nil {
			return "", wrap(err)
		}

		if err := enc.Close(); err != nil {
			return "", wrap(err)
		}

		return buf.String(), nil
	}

	ret, err := json.Marshal(cs)
	if err != nil {
		return "", wrap(err)
	}

	return string(ret), nil
}

func runSetupGenerateAcquis(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	fromFile := args[0]

	toDir, err := flags.GetString("to-dir")
	if err != nil {
		return err
	}

	input, err := os.ReadFile(fromFile)
	if err != nil {
		return fmt.Errorf("while reading setup file: %w", err)
	}

	output, err := setup.GenerateAcquis(input, toDir)
	if err != nil {
		return err
	}

	if toDir == "" {
		fmt.Println(output)
	}

	return nil
}

func runSetupInstallCollections(cmd *cobra.Command, args []string) error {
	flags := cmd.Flags()

	fromFile := args[0]

	dryRun, err := flags.GetBool("dry-run")
	if err != nil {
		return err
	}

	input, err := os.ReadFile(fromFile)
	if err != nil {
		return fmt.Errorf("while reading file %s: %w", fromFile, err)
	}

	if err = setup.InstallHubItems(csConfig, input, dryRun); err != nil {
		return err
	}

	return nil
}

func runSetupValidate(cmd *cobra.Command, args []string) error {
	fromFile := args[0]
	input, err := os.ReadFile(fromFile)
	if err != nil {
		return fmt.Errorf("while reading stdin: %w", err)
	}

	if err = setup.Validate(input); err != nil {
		fmt.Printf("%v\n", err)
		return fmt.Errorf("invalid setup file")
	}

	return nil
}
