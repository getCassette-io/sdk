package main

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/getCassette-io/sdk/controller"
	"github.com/getCassette-io/sdk/tui/views"
	"strings"
)

func populateWalletCard(w controller.Account) card {
	return card{tableData: []string{"Name: " + w.Address(), "ID: " + w.PublicKeyHexString()}, selected: 0}
}
func populateElementCard(el views.Element) card {
	fmt.Println("setting element ", el)
	return card{tableData: []string{"Name: " + el.Name, "ID: " + el.ID}, selected: 0}
}

type card struct {
	tableData []string
	selected  int // index of the selected button
}

func (m card) Init() tea.Cmd {
	return nil
}

func (m card) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "left", "h":
			if m.selected > 0 {
				m.selected--
			}
		case "right", "l":
			if m.selected < 1 {
				m.selected++
			}
			// Add more cases as necessary
		}
	}
	return m, nil
}

func (m card) View() string {
	var b strings.Builder

	// Render the table
	fmt.Println("row = ", m.tableData)
	for _, row := range m.tableData {

		fmt.Fprintf(&b, "%s\n", row)
	}
	b.WriteString("\n")
	// Render buttons
	buttons := []string{"OK", "Cancel"}
	for i, btn := range buttons {
		if i == m.selected {
			fmt.Fprintf(&b, "[%s] ", btn)
		} else {
			fmt.Fprintf(&b, " %s  ", btn)
		}
	}
	str := b.String()
	fmt.Println("b.String()--", str, "---")
	return str
}
