package main

import (
	"encoding/json"
	"log"
	"os"
	"os/signal"

	"golang.org/x/sys/windows"

	etw "github.com/MashaSamoylova/tracing-session"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Usage ./trace-session.exe <providerGUID>")
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	guid, err := windows.GUIDFromString(os.Args[1])
	if err != nil {
		log.Fatalf("Incorrect GUID given; %s", err)
	}

	session := etw.NewSession(guid, func(e *etw.Event) {
		log.Printf("Event %d from %s\n", e.Header.Id, e.Header.TimeStamp)
		if e.Header.Id != 11 {
			return
		}

		ext := e.ExtendedInfo()
		if ext.UserSID != nil {
			acc, _, _, _ := ext.UserSID.LookupAccount("")
			log.Printf("Event from %s -- %s\n", ext.UserSID.String(), acc)
		}
		_ = enc.Encode(ext)
		if data, err := e.EventProperties(); err == nil {
			_ = enc.Encode(data)
		}
	})

	go func() {
		log.Printf("Starting to listen ETW events from %s", guid)

		// Block until .Close().
		if err := session.SubscribeAndServe(); err != nil {
			log.Fatalf("Failed to SubscribeAndServe; %s", err)
		}

		log.Printf("Succesfully shut down")
	}()

	// Trap cancellation (the only signal values guaranteed to be present in
	// the os package on all systems are os.Interrupt and os.Kill).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	// Wait for stop and shutdown gracefully.
	for _ = range sigCh {
		log.Printf("Shutting the session down")

		err = session.Close()
		if err != nil {
			log.Printf("(!!!) Failed to stop session: %s\n", err)
		} else {
			return
		}
	}
}
