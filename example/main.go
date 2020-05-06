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
	/*fmt.Println(e.EventHeader.EventDescriptor.Id)

	if e.EventHeader.EventDescriptor.Id == 11 {
		spew.Dump(e.ParseExtendedInfo())
		spew.Dump(e.ParseEventProperties())
	}*/
}


func callback1(e *etw.Event) {
	select {}
	fmt.Println("Process:", e.EventHeader.EventDescriptor.Id, e.EventHeader.TimeStamp)
	/*fmt.Println(e.EventHeader.EventDescriptor.Id)

	if e.EventHeader.EventDescriptor.Id == 11 {
		spew.Dump(e.ParseExtendedInfo())
		spew.Dump(e.ParseEventProperties())
	}*/
}

func main() {
	session, err := etw.NewSession("TEST-GO-GO", callback)
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

	session1, err := etw.NewSession("TEST-GO-GO2", callback1)
	if err != nil {
		panic(err)
	}
	if err := session1.SubscribeToProvider("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"); err != nil {
		fmt.Println(err)
		err = session1.StopSession()
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

	wg.Add(2)
	go func() {
		defer wg.Done()
		err = session.StartSession()
		if err != nil {
			panic(err)
		}
	}()

	go func() {
		defer wg.Done()
		err = session1.StartSession()
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

		err = session1.StopSession()
		if err != nil {
			panic(err)
		}
	}()

	// Wait for stop and shutdown gracefully.
	<-sigCh

}
