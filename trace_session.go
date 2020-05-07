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

// NewSession creates windows trace session instance.
func NewSession(sessionName string, logFileName string, callback EventCallback) (Session, error) {
	var hSession C.TRACEHANDLE

	eventPropertiesSize := int(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{}))
	bufSize :=  eventPropertiesSize + len(sessionName) + len(logFileName) + 2 // for null symbols

	p := make([]byte, bufSize)

	properties := (C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&p[0]))
	properties.Wnode.BufferSize = C.ulong(bufSize)
	properties.Wnode.ClientContext = 1
	properties.Wnode.Flags = C.WNODE_FLAG_TRACED_GUID
	properties.LogFileMode = C.EVENT_TRACE_REAL_TIME_MODE | C.EVENT_TRACE_FILE_MODE_SEQUENTIAL
	properties.MaximumFileSize = 10 // mb TODO include this to config
	properties.LoggerNameOffset = C.ulong(eventPropertiesSize)
	properties.LogFileNameOffset = C.ulong(eventPropertiesSize + len(sessionName) + 1) // include null from session name string

	i := int(properties.LogFileNameOffset)
	for _, s := range logFileName {
		p[i] = byte(s)
		i++
	}

	status := C.StartTrace(&hSession, C.CString(sessionName), properties)
	if syscall.Errno(status) != windows.ERROR_SUCCESS {
		return Session{}, fmt.Errorf("failed to create session with %v", status)
	}

	return Session{
		callback:   callback,
		hSession:   hSession,
		properties: p,
		Name:       sessionName,
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
	params.EnableProperty = EVENT_ENABLE_PROPERTY_SID // TODO include this parameter to config
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
	if syscall.Errno(status) != windows.ERROR_SUCCESS &&
		syscall.Errno(status) != windows.ERROR_CANCELLED {
		return fmt.Errorf("failed start session with %v", status)
	}
	return nil
}

// StopSession stops trace session.
func (s *Session) StopSession() error {
	status := C.ControlTraceW(
		s.hSession,
		(*C.ushort)(unsafe.Pointer(nil)),
		(C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&s.properties[0])),
		EVENT_TRACE_CONTROL_STOP)

	// Note from windows documentation:
	// If you receive this error when stopping the session, ETW will have
	// already stopped the session before generating this error.
	if syscall.Errno(status) != windows.ERROR_MORE_DATA {
		return fmt.Errorf("failed to stop session with %v", status)
	}
	return nil
}

//export handleEvent
func handleEvent(eventRecord C.PEVENT_RECORD) {
	key := uint64(uintptr(eventRecord.UserContext))

	targetSession, ok := sessions.Load(key)
	if !ok {
		return
	}

	s := targetSession.(*Session)
	event := &Event{
		EventHeader: eventHeaderToGo(eventRecord.EventHeader),
		eventRecord: eventRecord,
	}

	s.callback(event)
}
