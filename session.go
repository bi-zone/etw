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

	guid          windows.GUID
	cgoKey        uintptr
	callback      EventCallback
	hSession      C.TRACEHANDLE
	propertiesBuf []byte
}

type EventCallback func(e *Event)

// NewSession creates windows trace session instance.
//
// TODO: specify unicode version by default?
// 		 https://github.com/msys2-contrib/mingw-w64/blob/master/mingw-w64-headers/include/evntrace.h#L702
func NewSession(sessionName string, callback EventCallback) (Session, error) {
	// We need to allocate a sequential buffer for a structure and a session name
	// which will be placed there by an API call (for the future calls).
	//
	// (Ref: https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header#members)
	//
	// The only way to do it in go -- unsafe cast of the allocated memory.
	eventPropertiesSize := int(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{}))
	bufSize := eventPropertiesSize + len(sessionName) + 1 // for null symbol
	propertiesBuf := make([]byte, bufSize)

	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
	properties := (C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&propertiesBuf[0]))
	properties.Wnode.BufferSize = C.ulong(bufSize)
	properties.Wnode.ClientContext = 2 // Use System time for event Timestamp
	properties.Wnode.Flags = C.WNODE_FLAG_TRACED_GUID

	// Mark that we are going to process events in real time using a callback.
	properties.LogFileMode = C.EVENT_TRACE_REAL_TIME_MODE

	// TODO: why to create session before the subscription if we can't
	// 		subscribe multiple times? (Or we can?)
	//		+ why to start session before the actual start collection?
	var hSession C.TRACEHANDLE
	ret := C.StartTrace(&hSession, C.CString(sessionName), properties)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return Session{}, fmt.Errorf("failed to create session; %w", status)
	}

	return Session{
		Name:          sessionName,
		callback:      callback,
		hSession:      hSession,
		propertiesBuf: propertiesBuf,
	}, nil
}

// SubscribeToProvider subscribes session to a provider.
func (s *Session) SubscribeToProvider(providerGUID string) error {
	// https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session

	guid, err := windows.GUIDFromString(providerGUID)
	if err != nil {
		return fmt.Errorf("failed to parse GUID; %w", err)
	}

	params := C.ENABLE_TRACE_PARAMETERS{
		Version:        2,                                  // ENABLE_TRACE_PARAMETERS_VERSION_2
		EnableProperty: C.ULONG(EVENT_ENABLE_PROPERTY_SID), // TODO include this parameter to config
	}

	// ULONG WMIAPI EnableTraceEx2(
	//	TRACEHANDLE              TraceHandle,
	//	LPCGUID                  ProviderId,
	//	ULONG                    ControlCode,
	//	UCHAR                    Level,
	//	ULONGLONG                MatchAnyKeyword,
	//	ULONGLONG                MatchAllKeyword,
	//	ULONG                    Timeout,
	//	PENABLE_TRACE_PARAMETERS EnableParameters
	// );
	ret := C.EnableTraceEx2(
		s.hSession,
		(*C.GUID)(unsafe.Pointer(&guid)),
		C.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		C.UCHAR(TRACE_LEVEL_VERBOSE), // TODO: configure or switch to C definitions
		0,                            // TODO: configure keywords matchers
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

	// ULONG StartSession(
	//	char* sessionName,
	//	PVOID context,
	//	PEVENT_RECORD_CALLBACK cb
	// );
	ret := C.StartSession(
		C.CString(s.Name),
		C.PVOID(s.cgoKey),
		C.PEVENT_RECORD_CALLBACK(C.handleEvent),
	)
	switch status := windows.Errno(ret); status {
	case windows.ERROR_SUCCESS, windows.ERROR_CANCELLED:
		runtime.SetFinalizer(s, func(s *Session) {
			freeSession(s.cgoKey)
		})
		return nil
	default:
		freeSession(s.cgoKey)
		return fmt.Errorf("failed start session; %w", status)
	}
}

// StopSession stops trace session and frees associated resources.
func (s *Session) StopSession() error {
	// Disabling providers before stopping the session.
	// MSDN docs:
	// https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session
	// "Be sure to disable all providers before stopping the session."

	// ULONG WMIAPI EnableTraceEx2(
	//	TRACEHANDLE              TraceHandle,
	//	LPCGUID                  ProviderId,
	//	ULONG                    ControlCode,
	//	UCHAR                    Level,
	//	ULONGLONG                MatchAnyKeyword,
	//	ULONGLONG                MatchAllKeyword,
	//	ULONG                    Timeout,
	//	PENABLE_TRACE_PARAMETERS EnableParameters
	// );

	ret := C.EnableTraceEx2(
		s.hSession,
		(*C.GUID)(unsafe.Pointer(&s.guid)),
		C.EVENT_CONTROL_CODE_DISABLE_PROVIDER,
		C.uchar(TRACE_LEVEL_VERBOSE), // TODO use config here
		0,                            // TODO use config here
		0,                            // TODO use config here
		0,                            // TODO use config here
		nil)

	// ULONG WMIAPI ControlTraceW(
	//  TRACEHANDLE             TraceHandle,
	//  LPCWSTR                 InstanceName,
	//  PEVENT_TRACE_PROPERTIES Properties,
	//  ULONG                   ControlCode
	// );
	ret = C.ControlTraceW(
		s.hSession,
		nil,
		(C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&s.propertiesBuf[0])),
		C.EVENT_TRACE_CONTROL_STOP)

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
	runtime.SetFinalizer(s, nil)

	// TODO: https://docs.microsoft.com/windows/desktop/ETW/closetrace ???
	// > If you are processing events from a log file, you call this function only after the ProcessTrace function returns.
	// (-__\\
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
	key := uintptr(eventRecord.UserContext)
	targetSession, ok := sessions.Load(key)
	if !ok {
		return
	}

	targetSession.(*Session).callback(&Event{
		Header:      eventHeaderToGo(eventRecord.EventHeader),
		eventRecord: eventRecord,
	})
}

// eventHeaderToGo converts windows EVENT_HEADER structure to go structure.
func eventHeaderToGo(header C.EVENT_HEADER) EventHeader {
	return EventHeader{
		EventDescriptor: eventDescriptorToGo(header.EventDescriptor),
		ThreadId:        uint32(header.ThreadId),
		ProcessId:       uint32(header.ProcessId),
		TimeStamp:       stampToTime(C.GetTimeStamp(header)),
		ProviderID:      windowsGuidToGo(header.ProviderId),
		ActivityId:      windowsGuidToGo(header.ActivityId),

		Flags:         uint16(header.Flags),
		KernelTime:    uint32(C.GetKernelTime(header)),
		UserTime:      uint32(C.GetUserTime(header)),
		ProcessorTime: uint64(C.GetProcessorTime(header)),
	}
}

// eventDescriptorToGo converts windows EVENT_DESCRIPTOR to go structure.
func eventDescriptorToGo(descriptor C.EVENT_DESCRIPTOR) EventDescriptor {
	return EventDescriptor{
		Id:      uint16(descriptor.Id),
		Version: uint8(descriptor.Version),
		Channel: uint8(descriptor.Channel),
		Level:   uint8(descriptor.Level),
		OpCode:  uint8(descriptor.Opcode),
		Task:    uint16(descriptor.Task),
		Keyword: uint64(descriptor.Keyword),
	}
}
