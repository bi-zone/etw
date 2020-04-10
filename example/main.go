package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	etw "github.com/MashaSamoylova/tracing-session"
	"github.com/davecgh/go-spew/spew"
)

var wg sync.WaitGroup

func processEvent(ctx context.Context, session etw.Session) {
	for {
		select {
		case e := <-session.Event():
			spew.Dump(e.EventHeader)
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
	session, err := etw.NewSession("TEST-GO-GO")
	if err != nil {
		panic(err)
	}
	if err := session.SubscribeToProvider("{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}"); err != nil {
		panic(err)
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

	time.Sleep(10 * time.Second)
	err = session.StopSession()
	if err != nil {
		panic(err)
	}
}
