package cliconsole

import (
	"io"

	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/crowdsecurity/crowdsec/cmd/crowdsec-cli/core/cstable"
	"github.com/crowdsecurity/crowdsec/pkg/csconfig"
	"github.com/crowdsecurity/crowdsec/pkg/emoji"
)

func cmdConsoleStatusTable(out io.Writer, wantColor string, consoleCfg csconfig.ConsoleConfig) {
	t := cstable.New(out, wantColor)
	t.SetRowLines(false)

	t.SetHeaders("Option Name", "Activated", "Description")
	t.SetHeaderAlignment(text.AlignLeft, text.AlignLeft, text.AlignLeft)

	consoleOptions := []struct {
		name        string
		enabled     bool
		description string
	}{
		{csconfig.SEND_CUSTOM_SCENARIOS, *consoleCfg.ShareCustomScenarios, "Forward alerts from custom scenarios to the console"},
		{csconfig.SEND_MANUAL_SCENARIOS, *consoleCfg.ShareManualDecisions, "Forward manual decisions to the console"},
		{csconfig.SEND_TAINTED_SCENARIOS, *consoleCfg.ShareTaintedScenarios, "Forward alerts from tainted scenarios to the console"},
		{csconfig.SEND_CONTEXT, *consoleCfg.ShareContext, "Forward context with alerts to the console"},
		{csconfig.CONSOLE_MANAGEMENT, *consoleCfg.ConsoleManagement, "Receive decisions from console"},
	}

	for _, option := range consoleOptions {
		activated := emoji.CrossMark
		if option.enabled {
			activated = emoji.CheckMarkButton
		}
		t.AddRow(option.name, activated, option.description)
	}

	t.Render()
}
