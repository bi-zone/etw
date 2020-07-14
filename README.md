# etw
[![GoDev](https://img.shields.io/static/v1?label=godev&message=reference&color=00add8&style=flat-square)](https://pkg.go.dev/github.com/bi-zone/etw)
[![Go Report Card](https://goreportcard.com/badge/github.com/bi-zone/etw)](https://goreportcard.com/report/github.com/bi-zone/etw)
[![Lint & Test Go code](https://img.shields.io/github/workflow/status/bi-zone/etw/Lint%20&%20Test%20Go%20code?style=flat-square)](https://github.com/bi-zone/etw/actions)


`etw` is a Go-package that allows you to receive [Event Tracing for Windows (ETW)](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
events in go code.

`etw` allows you to process events from new 
[TraceLogging](https://docs.microsoft.com/en-us/windows/win32/tracelogging/trace-logging-about) providers
as well as from classic (aka EventLog) providers, so you could actually listen to anything you can
see in Event Viewer window.

ETW API expects you to pass `stdcall` callback to process events, so `etw` **requires CGO** to be used. 
To use `etw` you need to have [mingw-w64](http://mingw-w64.org/) installed and pass some environment to the
Go compiler (take a look at [build/vars.sh](./build/vars.sh) and [examples/tracer/Makefile](./examples/tracer/Makefile)).

## Docs
Package reference is available at https://pkg.go.dev/github.com/bi-zone/etw

Examples are located in [examples](./examples) folder.

## Usage

```go
package main

import (
	"log"
	"os"
	"os/signal"
	"sync"

	"github.com/bi-zone/etw"
	"golang.org/x/sys/windows"
)

func main() {
	// Subscribe to Microsoft-Windows-DNS-Client
	guid, _ := windows.GUIDFromString("{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}")
	session, err := etw.NewSession(guid)
	if err != nil {
		log.Fatalf("Failed to create etw session: %s", err)
	}

	// Wait for "DNS query request" events to log outgoing DNS requests.
	cb := func(e *etw.Event) {
		if e.Header.ID != 3006 {
			return
		}
		if data, err := e.EventProperties(); err == nil && data["QueryType"] == "1" {
			log.Printf("PID %d just queried DNS for domain %v", e.Header.ProcessID, data["QueryName"])
		}
	}

	// `session.Process` blocks until `session.Close()`, so start it in routine.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		if err := session.Process(cb); err != nil {
			log.Printf("[ERR] Got error processing events: %s", err)
		}
		wg.Done()
	}()

	// Trap cancellation.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	<-sigCh

	if err := session.Close(); err != nil {
		log.Printf("[ERR] Got error closing the session: %s", err)
	}
	wg.Wait()
}

```

Note: to run the example you may need to pass CGO-specific variables to Go compiler, the easiest way to do it is:
```shell script
bash -c 'source ./build/vars.sh && go run main.go'
```

More sophisticated examples can be found in [examples](./examples) folder.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.