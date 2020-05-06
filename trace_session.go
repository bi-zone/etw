package tracing_session

/*
#cgo LDFLAGS: -ltdh

#include "session.h"

// handleEvent is exported from Go to CGO to guarantee C calling convention
// to be able to pass as a C callback function.
extern void handleEvent(PEVENT_RECORD e);
*/
import "C"
import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Session struct {
	Name string

	cgoKey     uintptr
	callback   EventCallback
	hSession   C.TRACEHANDLE
	properties C.PEVENT_TRACE_PROPERTIES
}

type EventCallback func(e *Event)

// NewSession creates windows trace session instance.
func NewSession(sessionName string, callback EventCallback) (Session, error) {
	var (
		hSession   C.TRACEHANDLE
		properties C.PEVENT_TRACE_PROPERTIES
	)

	// TODO: why to create session before the subscription if we can't
	// 		subscribe multiple times? (Or we can?)
	ret := C.CreateSession(&hSession, &properties, C.CString(sessionName))
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return Session{}, fmt.Errorf("failed to create session; %w", status)
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
		return fmt.Errorf("failed to parse GUID; %w", err)
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
	ret := C.EnableTraceEx2(
		s.hSession,
		(*C.GUID)(unsafe.Pointer(&guid)),
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_VERBOSE, // TODO: configure or switch to C definitions
		0,                   // TODO: configure keywords matchers
		0,
		0, // Timeout set to zero to enable the trace asynchronously
		&params)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return fmt.Errorf("failed to subscribe to provider; %w", status)
	}

	return nil
}

// StartSession starts event consuming from session.
// N.B. Blocking!
func (s *Session) StartSession() error {
	s.cgoKey = newSessionKey(s)
	runtime.SetFinalizer(s, func(s *Session) {
		freeSession(s.cgoKey)
	})

	ret := C.StartSession(
		C.CString(s.Name),
		C.PVOID(s.cgoKey),
		C.PEVENT_RECORD_CALLBACK(C.handleEvent),
	)
	switch status := windows.Errno(ret); status {
	case windows.ERROR_SUCCESS, windows.ERROR_CANCELLED:
		return nil
	default:
		freeSession(s.cgoKey)
		return fmt.Errorf("failed start session; %w", status)
	}
}

// StopSession stops trace session and frees associated resources.
func (s *Session) StopSession() error {
	// ULONG WMIAPI ControlTraceW(
	//  TRACEHANDLE             TraceHandle,
	//  LPCWSTR                 InstanceName,
	//  PEVENT_TRACE_PROPERTIES Properties,
	//  ULONG                   ControlCode
	// );
	ret := C.ControlTraceW(
		s.hSession,
		nil, // You must specify SessionName if SessionHandle is NULL.
		s.properties,
		EVENT_TRACE_CONTROL_STOP,
	)

	// If you receive ERROR_MORE_DATA when stopping the session, ETW will have
	// already stopped the session before generating this error.
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
	switch status := windows.Errno(ret); status {
	case windows.ERROR_MORE_DATA, windows.ERROR_SUCCESS:
		// All ok.
	default:
		return fmt.Errorf("failed to stop session; %w", status)
	}

	// TODO: free even on error?
	freeSession(s.cgoKey)
	C.free(unsafe.Pointer(s.properties))
	return nil
}

// We can't pass Go-land pointers to the C-world so we use a classical trick
// storing real pointers inside global map and passing to C "fake pointers"
// which are actually map keys.
var (
	sessions       sync.Map
	sessionCounter uintptr
)

// newSessionKey stores a @ptr inside a global storage returning its' key.
// After use the key should be freed using `freeSession`.
func newSessionKey(ptr *Session) uintptr {
	key := atomic.AddUintptr(&sessionCounter, 1)
	sessions.Store(key, ptr)

	return key
}

func freeSession(key uintptr) {
	sessions.Delete(key)
}

// handleEvent is exported to guarantee C calling convention and pass it as a
// callback to the ETW API.
//
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
