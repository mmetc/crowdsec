package setup

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/cwhub"
	goccyyaml "github.com/goccy/go-yaml"
	"gopkg.in/yaml.v3"
)

// AcquisDocument is created from a SetupItem. It represents a single YAML document, and can be part of a multi-document file.
type AcquisDocument struct {
	AcquisFilename   string            `yaml:"acquis_filename,omitempty"`
	Source           string            `yaml:"source"`
	Filenames        []string          `yaml:"filenames,omitempty"`
	JournalCTLFilter []string          `yaml:"journalctl_filter,omitempty"`
	Labels           map[string]string `yaml:"labels"`
}

func decodeSetup(input []byte, fancyErrors bool) (SetupEnvelope, error) {
	ret := SetupEnvelope{}

	// parse with goccy to have better error messages in many cases
	dec := goccyyaml.NewDecoder(bytes.NewBuffer(input), goccyyaml.Strict())

	if err := dec.Decode(&ret); err != nil {
		if fancyErrors {
			return ret, fmt.Errorf("%v", goccyyaml.FormatError(err, true, true))
		}
		// XXX errors here are multiline, should we just print them to stderr instead of logging?
		return ret, fmt.Errorf("%v", err)
	}

	// parse again because goccy is not strict enough anyway
	dec2 := yaml.NewDecoder(bytes.NewBuffer(input))
	dec2.KnownFields(true)

	if err := dec2.Decode(&ret); err != nil {
		return ret, fmt.Errorf("while unmarshaling setup file: %w", err)
	}

	return ret, nil
}

// InstallHubItems install the collections specified in a setup file.
func InstallHubItems(csConfig *csconfig.Config, input []byte, dryRun bool) error {
	setupEnvelope, err := decodeSetup(input, false)
	if err != nil {
		return err
	}

	if err := csConfig.LoadHub(); err != nil {
		return fmt.Errorf("loading hub: %w", err)
	}

	if err := cwhub.SetHubBranch(); err != nil {
		return fmt.Errorf("setting hub branch: %w", err)
	}

	if err := cwhub.GetHubIdx(csConfig.Hub); err != nil {
		return fmt.Errorf("getting hub index: %w", err)
	}

	for _, setupItem := range setupEnvelope.Setup {
		forceAction := false
		downloadOnly := false

		if setupItem.Collection != "" {
			if dryRun {
				fmt.Println("dry-run: would install collection", setupItem.Collection)

				continue
			}

			if err := cwhub.InstallItem(csConfig, setupItem.Collection, cwhub.COLLECTIONS, forceAction, downloadOnly); err != nil {
				return fmt.Errorf("while installing collection: %w", err)
			}
		}
	}

	return nil
}

// marshalAcquisDocuments creates the monolithic file, or itemized files (if a directory is provided) with the acquisition documents.
func marshalAcquisDocuments(ads []AcquisDocument, toDir string) (string, error) {
	var sb strings.Builder

	dashTerminator := false

	if toDir != "" {
		_, err := os.Stat(toDir)
		if os.IsNotExist(err) {
			return "", fmt.Errorf("directory %s does not exist", toDir)
		}
	}

	for _, ad := range ads {
		adOut := ad
		// this is only used to know the name of the yaml file
		adOut.AcquisFilename = ""

		out, err := goccyyaml.MarshalWithOptions(adOut, goccyyaml.IndentSequence(true))
		if err != nil {
			return "", fmt.Errorf("while encoding acquis item: %w", err)
		}

		if toDir != "" {
			if ad.AcquisFilename == "" {
				return "", fmt.Errorf("empty acquis filename")
			}

			fname := filepath.Join(toDir, ad.AcquisFilename)
			fmt.Println("creating", fname)

			f, err := os.Create(fname)
			if err != nil {
				return "", fmt.Errorf("creating acquisition file: %w", err)
			}
			defer f.Close()

			_, err = f.Write(out)
			if err != nil {
				return "", fmt.Errorf("while writing to %s: %w", ad.AcquisFilename, err)
			}

			f.Sync()

			continue
		}

		if dashTerminator {
			sb.WriteString("---\n")
		}

		sb.Write(out)

		dashTerminator = true
	}

	return sb.String(), nil
}

// Validate checks the validity of a setup file.
func Validate(input []byte) error {
	_, err := decodeSetup(input, true)
	if err != nil {
		return err
	}
	return nil
}

// GenerateAcquis generates the acquisition documents from a setup file.
func GenerateAcquis(input []byte, toDir string) (string, error) {
	setupEnvelope, err := decodeSetup(input, false)
	if err != nil {
		return "", err
	}

	ads := make([]AcquisDocument, 0)

	filename := func(basename string, ext string) string {
		if basename == "" {
			return basename
		}

		return basename + ext
	}

	for _, setupItem := range setupEnvelope.Setup {
		acquis := setupItem.Acquis

		basename := ""
		if toDir != "" {
			basename = "setup." + setupItem.DetectedService
		}

		if len(acquis.LogFiles) > 0 {
			ad := AcquisDocument{
				AcquisFilename: filename(basename, ".yaml"),
				Source:         "file",
				Filenames:      acquis.LogFiles,
				Labels:         acquis.Labels,
			}
			ads = append(ads, ad)
		}

		if len(acquis.JournalCTLFilter) > 0 {
			ad := AcquisDocument{
				AcquisFilename:   filename(basename, ".systemd.yaml"),
				Source:           "journalctl",
				JournalCTLFilter: acquis.JournalCTLFilter,
				Labels: map[string]string{
					"type": "journald",
				},
			}
			ads = append(ads, ad)
		}
	}

	return marshalAcquisDocuments(ads, toDir)
}
