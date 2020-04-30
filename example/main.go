package main

import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"os"
	"os/signal"
	"sync"

	etw "github.com/MashaSamoylova/tracing-session"
)

var wg sync.WaitGroup

func callback(e *etw.Event) {
	fmt.Println(e.Header.Descriptor.Id)

	if e.Header.Descriptor.Id == 11 {
		spew.Dump(e.ParseExtendedInfo())
		spew.Dump(e.ParseEventProperties())
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage ./trace-session.exe <providerGUID>")
		return
	}

	session, err := etw.NewSession("TEST-GO-GO", callback)
	if err != nil {
		panic(err)
	}
	if err := session.SubscribeToProvider(os.Args[1]); err != nil {
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
