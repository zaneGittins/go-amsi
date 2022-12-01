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
	ContentBase64   string `json:"contentBase64"`
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
		pterm.Error.Printf("Failed to subscribe to ETW using guid %s: %s", guid, err)
		os.Exit(-1)
	} else {
		pterm.DefaultBigText.WithLetters(pterm.NewLettersFromString("AMSI Events")).Render()
		pterm.DefaultParagraph.Println("Author: Zane Gittins")
		pterm.DefaultParagraph.Println("Version: v0.0.1")
		pterm.Success.Printf("Successfully subscribed to ETW using GUID: %v\n", guid)
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

			hash := data["hash"].(string)

			// Populate AMSIEvent struct with data.
			event := AMSIEvent{AppName: data["appname"].(string),
				Content:         decodedContent[:10],
				ContentFiltered: data["contentFiltered"].(string),
				ContentName:     data["contentname"].(string),
				ContentSize:     data["contentsize"].(string),
				Hash:            hash,
				OriginalSize:    data["originalsize"].(string),
				ScanResult:      data["scanResult"].(string),
				ScanStatus:      data["scanStatus"].(string),
				Session:         data["session"].(string),
			}

			err = os.WriteFile((hash + ".bin"), contentBytes, 0755)
			if err != nil {
				fmt.Printf("Unable to write file: %v", err)
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
