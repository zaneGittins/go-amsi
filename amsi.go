package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"

	"github.com/bi-zone/etw"
	"github.com/hokaccha/go-prettyjson"
	"github.com/pterm/pterm"
	"golang.org/x/sys/windows"
)

// AMSIEvent
type AMSIEvent struct {
	AppName         string `json:"appname"`
	Content         string `json:"content"`
	ContentFiltered string `json:"contentFiltered"`
	ContentName     string `json:"contentname"`
	ContentSize     string `json:"contentsize"`
	Hash            string `json:"hash"`
	OriginalSize    string `json:"originalsize"`
	ScanResult      string `json:"scanResult"`
	ScanStatus      string `json:"scanStatus"`
	Session         string `json:"session"`
}

func main() {

	// Subscribe to Microsoft-Antimalware-Scan-Interface
	// Found GUID using logman query providers Microsoft-Antimalware-Scan-Interface
	guid, _ := windows.GUIDFromString("{2A576B87-09A7-520E-C21A-4942F0271D67}")
	session, err := etw.NewSession(guid)
	if err != nil {
		pterm.Error.Printf("Failed to create etw session: %s", err)
		os.Exit(-1)
	} else {
		pterm.Success.Printf("Successfully subscribed to GUID: %v\n", guid)
	}

	// Wait for AMSI events.
	cb := func(e *etw.Event) {
		if data, err := e.EventProperties(); err == nil {

			// Convert string to byte slice using hex decode, remove the first two characters first "0x".
			contentBytes, err := hex.DecodeString(data["content"].(string)[2:])
			if err != nil {
				fmt.Println(data["content"].(string))
				panic(err)
			}
			decodedContent := string(contentBytes)
			decodedContent = strings.Replace(decodedContent, "\x00", "", -1)

			// Populate AMSIEvent struct with data.
			event := AMSIEvent{AppName: data["appname"].(string),
				Content:         decodedContent,
				ContentFiltered: data["contentFiltered"].(string),
				ContentName:     data["contentname"].(string),
				ContentSize:     data["contentsize"].(string),
				Hash:            data["hash"].(string),
				OriginalSize:    data["originalsize"].(string),
				ScanResult:      data["scanResult"].(string),
				ScanStatus:      data["scanStatus"].(string),
				Session:         data["session"].(string),
			}

			// Print the AMSI event to console.
			eventPretty, _ := prettyjson.Marshal(event)
			fmt.Printf("%s\n", string(eventPretty))
		}
	}

	// `session.Process` blocks until `session.Close()`, so start it in routine.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		if err := session.Process(cb); err != nil {
			pterm.Error.Printf("[ERR] Got error processing events: %s", err)
		}
		wg.Done()
	}()

	// Trap cancellation.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh

	if err := session.Close(); err != nil {
		pterm.Error.Printf("[ERR] Got error closing the session: %s", err)
	}
	wg.Wait()
}
