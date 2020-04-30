package tracing_session

/*
#cgo LDFLAGS: -ltdh

#include "session.h"

extern void handleEvent(PEVENT_RECORD e);
*/
import "C"
import (
	"fmt"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NewSession creates windows trace session instance.
func NewSession(sessionName string, callback EventCallback) (Session, error) {
	var (
		hSession   C.TRACEHANDLE
		properties C.PEVENT_TRACE_PROPERTIES
	)

	// TODO: why to create session before the subscription if we can't
	// 		subscribe multiple times? (Or we can?)
	status := C.CreateSession(&hSession, &properties, C.CString(sessionName))
	if windows.Errno(status) != windows.ERROR_SUCCESS {
		return Session{}, fmt.Errorf("failed to create session with %v", status)
	}

	return Session{
		callback:   callback,
		hSession:   hSession,
		properties: properties,
		Name:       sessionName,
	}, nil
}

// SubscribeToProvider subscribes session to a provider.
func (s *Session) SubscribeToProvider(providerGUID string) error {
	guid, err := windows.GUIDFromString(providerGUID)
	if err != nil {
		return fmt.Errorf("failed to parse GUID from string %s", err)
	}

	params := C.ENABLE_TRACE_PARAMETERS{
		Version:        2,                         // ENABLE_TRACE_PARAMETERS_VERSION_2
		EnableProperty: EVENT_ENABLE_PROPERTY_SID, // TODO include this parameter to config
		SourceId:       s.properties.Wnode.Guid,
	}

	//	ULONG WMIAPI EnableTraceEx2(
	//		TRACEHANDLE              TraceHandle,
	//		LPCGUID                  ProviderId,
	//		ULONG                    ControlCode,
	//		UCHAR                    Level,
	//		ULONGLONG                MatchAnyKeyword,
	//		ULONGLONG                MatchAllKeyword,
	//		ULONG                    Timeout,
	//		PENABLE_TRACE_PARAMETERS EnableParameters
	//	);
	status := C.EnableTraceEx2(
		s.hSession,
		(*C.GUID)(unsafe.Pointer(&guid)),
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_VERBOSE, // TODO: configure or switch to C definitions
		0,                   // TODO: configure keywords matchers
		0,
		0, // Timeout set to zero to enable the trace asynchronously
		&params)

	if windows.Errno(status) != windows.ERROR_SUCCESS {
		return fmt.Errorf("failed to subscribe to provider with %d", status)
	}

	return nil
}

// StartSession starts event consuming from session.
// N.B. Blocking!
func (s *Session) StartSession() error {
	key := atomic.AddUint64(&sessionCounter, 1)
	sessions.Store(key, s)

	status := C.StartSession(C.CString(s.Name), C.PVOID(uintptr(key)), C.PEVENT_RECORD_CALLBACK(C.handleEvent))
	switch windows.Errno(status) {
	case windows.ERROR_SUCCESS, windows.ERROR_CANCELLED:
		return nil
	default:
		return fmt.Errorf("failed start session with %v", status) // TODO: GetLastError?
	}
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
	//
	// TODO: not handling ERROR_SUCCESS??
	if windows.Errno(status) != windows.ERROR_MORE_DATA {
		return fmt.Errorf("failed to stop session with %v", status)
	}
	C.free(unsafe.Pointer(s.properties))
	return nil
}

// TODO: Comment the trick with Map.
var (
	sessions       sync.Map
	sessionCounter uint64
)

//export handleEvent
func handleEvent(eventRecord C.PEVENT_RECORD) {
	key := uint64(uintptr(eventRecord.UserContext))
	targetSession, ok := sessions.Load(key)
	if !ok {
		return
	}

	targetSession.(*Session).callback(&Event{
		Header:      eventHeaderToGo(eventRecord.EventHeader),
		eventRecord: eventRecord,
	})
}
