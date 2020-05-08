package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sync"

	etw "github.com/MashaSamoylova/tracing-session"
)

var wg sync.WaitGroup

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage ./trace-session.exe <providerGUID>")
		return
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	session, err := etw.NewSession("TEST-GO-GO", "test.etl", func(e *etw.Event) {
		fmt.Println(e.Header.Id)
		if e.Header.Id != 11 {
			return
		}

		ext := e.ExtendedInfo()
		if ext.UserSID != nil {
			acc, _, _, _ := ext.UserSID.LookupAccount("")
			fmt.Printf("Event from %s -- %s", ext.UserSID.String(), acc)
		}
		_ = enc.Encode(ext)
		if data, err := e.EventProperties(); err == nil {
			_ = enc.Encode(data)
		}
	})
	if err != nil {
		panic(err)
	}
	if err := session.SubscribeToProvider("{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}"); err != nil {
		fmt.Println(err)
		err = session.StopSession()
		if err != nil {
			panic(err)
		}
		return
	}

	// Test that all goroutines are finished.
	defer func() {
		wg.Wait()
		fmt.Println("Session is closed")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		err = session.StartSession()
		if err != nil {
			panic(err)
		}
	}()

	// Trap cancellation (the only signal values guaranteed to be present in
	// the os package on all systems are os.Interrupt and os.Kill).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	defer func() {
		err = session.StopSession()
		if err != nil {
			panic(err)
		}
	}()

	// Wait for stop and shutdown gracefully.
	<-sigCh

}
