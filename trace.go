package tracing_session

/*
#cgo LDFLAGS: -ltdh

#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7

#include "session.h"

*/
import "C"
import (
	"fmt"
	"math/rand"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var sessions sync.Map

type Session struct {
	hSession   C.TRACEHANDLE
	properties C.PEVENT_TRACE_PROPERTIES
	Name       string

	errChan   chan error
	eventChan chan *Event
}

func (s *Session) Error() chan error {
	return s.errChan
}

func (s *Session) Event() chan *Event {
	return s.eventChan
}

// NewSession creates windows trace session instance.
func NewSession(sessionName string) (Session, error) {
	var hSession C.TRACEHANDLE
	var properties C.PEVENT_TRACE_PROPERTIES

	status := C.CreateSession(&hSession, &properties, C.CString(sessionName))

	if status != 0 {
		return Session{}, fmt.Errorf("failed to create session with %v", status)
	}

	return Session{
		hSession:   hSession,
		properties: properties,
		Name:       sessionName,

		errChan:   make(chan error),
		eventChan: make(chan *Event),
	}, nil
}

// SubscribeToProvider subscribes session to a provider.
func (s *Session) SubscribeToProvider(providerGUID string) error {
	guid, err := windows.GUIDFromString(providerGUID)
	if err != nil {
		return fmt.Errorf("failed to parse GUID from string %s", err)
	}

	var params C.ENABLE_TRACE_PARAMETERS

	params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2
	params.EnableProperty = EVENT_ENABLE_PROPERTY_SID
	params.SourceId = s.properties.Wnode.Guid
	params.ControlFlags = 0
	params.EnableFilterDesc = nil
	params.FilterDescCount = 0

	status := C.EnableTraceEx2(
		s.hSession,
		(*C.GUID)(unsafe.Pointer(&guid)),
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_VERBOSE,
		0, // TODO config
		0,
		0,
		&params)

	if status != 0 {
		return fmt.Errorf("failed to subscribe to provider with %d", status)
	}

	return nil
}

// This structure has not FilterDescCount field in the mingw header file.
// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-enable_trace_parameters
type EnableTraceParameters struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32
	SourceId         windows.GUID
	EnableFilterDesc C.PEVENT_FILTER_DESCRIPTOR
	FilterDescCount  uint32
}

// StartSession starts event consuming from session.
// N.B. Blocking!
func (s *Session) StartSession() error {
	key := rand.Int()
	sessions.Store(key, s)
	status := C.StartSession(C.CString(s.Name), C.PVOID(uintptr(key)))
	if status != 0 {
		return fmt.Errorf("failed start session with %v", status)
	}
	return nil
}

// StopSession stops trace session.
func (s *Session) StopSession() error {
	status := C.ControlTraceW(s.hSession, (*C.ushort)(unsafe.Pointer(nil)), s.properties, EVENT_TRACE_CONTROL_STOP)

	// Note from windows documentation:
	// If you receive this error when stopping the session, ETW will have
	// already stopped the session before generating this error.
	if status != ERROR_MORE_DATA {
		return fmt.Errorf("fail to stop session with %v", status)
	}
	C.free(unsafe.Pointer(s.properties))
	return nil
}

//export handleEvent
func handleEvent(eventRecord C.PEVENT_RECORD) {
	key := int(uintptr(eventRecord.UserContext))
	targetSession, _ := sessions.Load(key)
	s := targetSession.(*Session)

	event, err := parseEvent(eventRecord)
	if err != nil {
		s.errChan <- err
	} else {
		s.eventChan <- event
	}
}

// Event represents parsing result from structure:
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record
type Event struct {
	EventHeader  EventHeader
	ExtendedData map[string]interface{}
	Properties   map[string]interface{}
}

// EventHeader consists common event information.
type EventHeader struct {
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       time.Time
	EventDescriptor EventDescriptor
	ProviderID      windows.GUID
	KernelTime      uint32
	UserTime        uint32
	ActivityId      windows.GUID
}

// Go-analog of EVENT_DESCRIPTOR structure.
// https://docs.microsoft.com/ru-ru/windows/win32/api/evntprov/ns-evntprov-event_descriptor
type EventDescriptor struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	OpCode  uint8
	Task    uint16
	Keyword uint64
}

const (
	ENABLE_TRACE_PARAMETERS_VERSION   = 1
	ENABLE_TRACE_PARAMETERS_VERSION_2 = 2

	EVENT_ENABLE_PROPERTY_SID               = 0x001
	EVENT_ENABLE_PROPERTY_TS_ID             = 0x002
	EVENT_ENABLE_PROPERTY_STACK_TRACE       = 0x004
	EVENT_ENABLE_PROPERTY_PSM_KEY           = 0x008
	EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0  = 0x010
	EVENT_ENABLE_PROPERTY_PROVIDER_GROUP    = 0x020
	EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0  = 0x040
	EVENT_ENABLE_PROPERTY_PROCESS_START_KEY = 0x080
	EVENT_ENABLE_PROPERTY_EVENT_KEY         = 0x100
	EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE = 0x200
)
