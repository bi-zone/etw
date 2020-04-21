package main

import (
	"context"
	"fmt"
	etw "github.com/MashaSamoylova/tracing-session"
	"github.com/davecgh/go-spew/spew"
	"os"
	"os/signal"
	"sync"
)

var wg sync.WaitGroup

func processEvent(ctx context.Context, session etw.Session) {
	for {
		select {
		case e := <-session.Event():
			spew.Dump(e)
		case err := <-session.Error():
			panic(err)
		case <-ctx.Done():
			fmt.Println("Event processing is finished")
			wg.Done()
			return
		}
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage ./trace-session.exe <providerGUID>")
		return
	}

	session, err := etw.NewSession("TEST-GO-GO")
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

	ctx, cancel := context.WithCancel(context.Background())
	go processEvent(ctx, session)

	// Test that all goroutines are finished.
	defer func() {
		wg.Wait()
		fmt.Println("Session is closed")

		wg.Add(1)
		cancel()
		wg.Wait()
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
