package main

import (
	"fmt"
	etw "github.com/MashaSamoylova/tracing-session"
	"os"
	"os/signal"
	"sync"
)

var wg sync.WaitGroup

func callback(e *etw.Event) {
	fmt.Println("wmi:", e.EventHeader.EventDescriptor.Id, e.EventHeader.TimeStamp)
}


func main() {
	session, err := etw.NewSession("TEST-GO-GO", "test2.etl", callback)
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
