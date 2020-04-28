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
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	sessions       sync.Map
	sessionCounter uint64
)

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

	if syscall.Errno(status) != windows.ERROR_SUCCESS {
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

	if syscall.Errno(status) != windows.ERROR_SUCCESS {
		return fmt.Errorf("failed to subscribe to provider with %d", status)
	}

	return nil
}

// StartSession starts event consuming from session.
// N.B. Blocking!
func (s *Session) StartSession() error {
	key := atomic.AddUint64(&sessionCounter, 1)
	sessions.Store(key, s)
	status := C.StartSession(C.CString(s.Name), C.PVOID(uintptr(key)))
	if status != 0 {
		return fmt.Errorf("failed start session with %v", status)
	}
	return nil
}

// StopSession stops trace session.
func (s *Session) StopSession() error {
	status := C.ControlTraceW(
		s.hSession,
		(*C.ushort)(unsafe.Pointer(nil)),
		s.properties,
		EVENT_TRACE_CONTROL_STOP)

	// Note from windows documentation:
	// If you receive this error when stopping the session, ETW will have
	// already stopped the session before generating this error.
	if syscall.Errno(status) != windows.ERROR_MORE_DATA {
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
