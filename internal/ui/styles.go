package ui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

var (
	primaryColor   = lipgloss.Color("#B4A7D6")
	successColor   = lipgloss.Color("#A8E6CF")
	errorColor     = lipgloss.Color("#FFB3BA")
	warningColor   = lipgloss.Color("#FFE5B4")
	mutedColor     = lipgloss.Color("#C5C6C8")
	highlightColor = lipgloss.Color("#B3D9FF")
	tipColor       = lipgloss.Color("#FFD4A3")

	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor).
			MarginTop(1).
			MarginBottom(1)

	SuccessStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(successColor)

	ErrorStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(errorColor)

	WarningStyle = lipgloss.NewStyle().
			Foreground(warningColor)

	MutedStyle = lipgloss.NewStyle().
			Foreground(mutedColor)

	HighlightStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(highlightColor)

	TipStyle = lipgloss.NewStyle().
			Foreground(tipColor)

	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(primaryColor).
			Padding(1, 2).
			MarginTop(1).
			MarginBottom(1)

	PromptStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true)

	ListItemStyle = lipgloss.NewStyle().
			Foreground(highlightColor).
			PaddingLeft(2)
)

func PrintTitle(text string) {
	banner := lipgloss.NewStyle().
		Bold(true).
		Foreground(primaryColor).
		Border(lipgloss.DoubleBorder()).
		BorderForeground(primaryColor).
		Padding(0, 2).
		Render(text)
	fmt.Println()
	fmt.Println(banner)
	fmt.Println()
}

func PrintSuccess(icon, message string) {
	fmt.Println(SuccessStyle.Render(fmt.Sprintf("%s %s", icon, message)))
}

func PrintError(icon, message string) {
	fmt.Println(ErrorStyle.Render(fmt.Sprintf("%s %s", icon, message)))
}

func PrintWarning(icon, message string) {
	fmt.Println(WarningStyle.Render(fmt.Sprintf("%s %s", icon, message)))
}

func PrintInfo(icon, message string) {
	fmt.Println(HighlightStyle.Render(fmt.Sprintf("%s %s", icon, message)))
}

func PrintMuted(message string) {
	fmt.Println(MutedStyle.Render(message))
}

func PrintPrompt(message string) {
	fmt.Print(PromptStyle.Render(message))
}

func PrintBox(content string) {
	fmt.Println(BoxStyle.Render(content))
}

func PrintListItem(icon, name string) {
	fmt.Println(ListItemStyle.Render(fmt.Sprintf("%s %s", icon, name)))
}

func PrintDivider() {
	PrintDividerWidth(41)
}

func PrintDividerWidth(width int) {
	if width < 1 {
		width = 41
	}
	dividerStr := ""
	for i := 0; i < width; i++ {
		dividerStr += "─"
	}
	divider := lipgloss.NewStyle().
		Foreground(primaryColor).
		Render(dividerStr)
	fmt.Println(divider)
}

func PrintHighlight(message string) {
	styled := HighlightStyle.Render(message)
	fmt.Print(styled)
}

func PrintTip(message string) {
	fmt.Println(TipStyle.Render(message))
}
