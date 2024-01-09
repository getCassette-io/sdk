.PHONY: tui

tui:
	go build -o ./out/tui ./tui && ./out/tui
