package tracing_session

/*
#cgo LDFLAGS: -ggdb -ltdh
#include "session.h"
*/
import "C"
import (
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"golang.org/x/sys/windows"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"math/rand"
)

var (
	api32 = windows.NewLazySystemDLL("Advapi32.dll")
)

var sessions sync.Map

var procEnableTraceEx2 = api32.NewProc("EnableTraceEx2")

const EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
const TRACE_LEVEL_VERBOSE = 5

type Session struct {
	hSession *C.TRACEHANDLE
	Name     string
}

func NewSession(sessionName string) (Session, error) {
	var hSession C.TRACEHANDLE
	status := C.CreateSession(&hSession, C.CString(sessionName))
	spew.Dump(status)

	return Session{
		hSession: &hSession,
		Name: sessionName,
	}, nil
}

func (s *Session) SubscribeToProvider(providerGUID string) error {
	guid, _ := windows.GUIDFromString(providerGUID)
	_, _, status := syscall.Syscall9(procEnableTraceEx2.Addr(),
		8,
		uintptr(*s.hSession),
		uintptr(unsafe.Pointer(&guid)),
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_VERBOSE,
		0,
		0,
		0,
		0,
		0)
	spew.Dump(status)
	return nil
}

type EventCallback func(event C.PEVENT_RECORD)

//export handleEvent
func handleEvent(event C.PEVENT_RECORD) {
	parseEvent(event)
	key := int(uintptr(event.UserContext))
	targetSession, _  := sessions.Load(key)
	s := targetSession.(*Session)
	fmt.Println(s.Name)
}

// Go-analog of EVENT_RECORD structure.
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record

type Event struct {
	EventHeader EventHeader
	Properties map[string]interface{}
}

type EventHeader struct {
	Size uint16
	HeaderType uint16
	Flags uint16
	EventProperty uint16
	ThreadId uint32
	ProcessId uint32
	TimeStamp time.Time
	EventDescriptor EventDescriptor
	GUID windows.GUID
	ActivityId windows.GUID
}

type EventDescriptor struct {
	Id uint16
	Version uint8
	Channel uint8
	Level uint8
	OpCode uint8
	Task uint16
	Keyword  uint64
}

// https://docs.microsoft.com/ru-ru/windows/win32/etw/using-tdhformatproperty-to-consume-event-data
// https://github.com/microsoft/perfview/blob/master/src/TraceEvent/TraceEvent.cs
// https://docs.microsoft.com/en-us/windows/win32/etw/retrieving-event-metadata
func parseEvent(event C.PEVENT_RECORD) Event{
	traceEventInfo, _ := getEventInformation(event)
	spew.Dump(traceEventInfo)
	return Event{}
}

func getEventInformation(pEvent C.PEVENT_RECORD) (C.PTRACE_EVENT_INFO, error) {
	var eventInfo C.PTRACE_EVENT_INFO
	var bufferSize C.int

	// get structure size
	status := C.TdhGetEventInformation(pEvent, 0, nil, &eventInfo, &bufferSize)

	if C.ERROR_INSUFFICIENT_BUFFER == status {
		pInfo := C.TRACE_EVENT_INFO*(C.malloc(bufferSize))
		if pInfo == 0  {
			return nil, fmt.Errorf("failed to allocate memory for event info (size=%v)", bufferSize)
		}

		status = C.TdhGetEventInformation(pEvent, 0, nil, &eventInfo, &bufferSize)
	}
	if C.ERROR_SUCCESS != status {
		return nil, fmt.Errorf("TdhGetEventInformation failed with %v", status)
	}
	return eventInfo, nil
}



func (s *Session) StartSession() error {
	key := rand.Int()
	sessions.Store(key, s)
	status := C.StartSession(C.CString(s.Name), C.PVOID(uintptr(key)))
	spew.Dump(status)
	return nil
}
