//+build windows

package etw

/*
#cgo LDFLAGS: -ltdh

#include "session.h"
*/
import "C"
import (
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Session struct {
	guid     windows.GUID
	config   SessionOptions
	callback EventCallback

	etwSessionName []uint16
	hSession       C.TRACEHANDLE
	propertiesBuf  []byte
}

type EventCallback func(e *Event)

type ExistError struct {
	Name string
}

func (e ExistError) Error() string {
	return fmt.Sprintf("session %q already exist", e.Name)
}

// NewSession creates windows trace session instance.
func NewSession(providerGUID windows.GUID, options ...Option) (*Session, error) {
	defaultConfig := SessionOptions{
		Name:  "go-etw-" + randomName(),
		Level: TRACE_LEVEL_VERBOSE,
	}
	for _, opt := range options {
		opt(&defaultConfig)
	}
	s := Session{
		guid:   providerGUID,
		config: defaultConfig,
	}

	utf16Name, err := windows.UTF16FromString(s.config.Name)
	if err != nil {
		return nil, fmt.Errorf("incorrect session name; %w", err) // unlikely
	}
	s.etwSessionName = utf16Name

	// TODO: Review the order and necessity of all setup calls.

	if err := s.createETWSession(); err != nil {
		return nil, fmt.Errorf("failed to create session; %w", err)
	}

	return &s, nil
}

// Process starts event consuming from session.
// N.B. Blocking!
func (s *Session) Process(cb EventCallback) error {
	s.callback = cb

	if err := s.subscribeToProvider(); err != nil {
		return fmt.Errorf("failed to subscribe to provider; %w", err)
	}

	cgoKey := newCallbackKey(s)
	defer freeCallbackKey(cgoKey)

	// Will block here until being closed.
	if err := s.processEvents(cgoKey); err != nil {
		return fmt.Errorf("error processing events; %w", err)
	}
	return nil
}

// UpdateOptions changes session parameters on runtime.
//
// You can change following options:
// - WithLevel(lvl TraceLevel)
// - WithMatchKeywords(anyKeyword, allKeyword uint64)
// - WithProperty(p EnableProperty)
func (s *Session) UpdateOptions(options ...Option) error {
	for _, opt := range options {
		opt(&s.config)
	}
	if err := s.subscribeToProvider(); err != nil {
		return err
	}
	return nil
}

// Close stops trace session and frees associated resources.
func (s *Session) Close() error {
	// "Be sure to disable all providers before stopping the session."
	// https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session
	if err := s.unsubscribeFromProvider(); err != nil {
		return fmt.Errorf("failed to disable provider; %w", err)
	}

	if err := s.stopSession(); err != nil {
		return fmt.Errorf("failed to stop session; %w", err)
	}
	return nil
}

// KillSession forces the session to stop by name.
//
// We should unsubscribe the session from all providers before
// stopping the session (For proper session disabling see `Close` function).
// We didn't find the way how to get a list of providers by session name
// using windows API. We stop the session without unsubscribing it
// from providers.
func KillSession(name string) error {
	const (
		maxLengthLogfileName = 1024
	)

	nameUTF16, err := windows.UTF16FromString(name)
	if err != nil {
		return fmt.Errorf("failed to convert session name to utf16")
	}
	sessionNameLength := len(nameUTF16) * int(unsafe.Sizeof(nameUTF16[0]))

	// Initializing the empty EVENT_TRACE_PROPERTIES structure.
	eventPropertiesSize := int(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{}))
	// We don't know if this session was opened with the log file or not
	// (session could be opened without our library).
	// That's why we allocate memory for LogFile name too.
	bufSize := eventPropertiesSize + sessionNameLength + maxLengthLogfileName
	propertiesBuf := make([]byte, bufSize)
	pProperties := (C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&propertiesBuf[0]))
	pProperties.Wnode.BufferSize = C.ulong(bufSize)

	// ULONG WMIAPI ControlTraceW(
	//  TRACEHANDLE             TraceHandle,
	//  LPCWSTR                 InstanceName,
	//  PEVENT_TRACE_PROPERTIES Properties,
	//  ULONG                   ControlCode
	// );
	ret := C.ControlTraceW(
		0,
		(*C.ushort)(unsafe.Pointer(&nameUTF16[0])),
		pProperties,
		C.EVENT_TRACE_CONTROL_STOP)

	// If you receive ERROR_MORE_DATA when stopping the session, ETW will have
	// already stopped the session before generating this error.
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
	switch status := windows.Errno(ret); status {
	case windows.ERROR_MORE_DATA, windows.ERROR_SUCCESS:
		return nil
	default:
		return status
	}
}

// createETWSession creates a ETW session that would manage  wraps StartTraceW.
func (s *Session) createETWSession() error {
	// utf16Name is already null-terminated, so no additional nulls further

	// We need to allocate a sequential buffer for a structure and a session name
	// which will be placed there by an API call (for the future calls).
	//
	// (Ref: https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header#members)
	//
	// The only way to do it in go -- unsafe cast of the allocated memory.
	eventPropertiesSize := int(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{}))
	bufSize := eventPropertiesSize + len(s.etwSessionName)*int(unsafe.Sizeof(s.etwSessionName[0]))
	propertiesBuf := make([]byte, bufSize)

	// We will use Query Performance Counter for timestamp cos it gives us higher
	// time resolution. Event timestamps however would be converted to the common
	// FileTime due to absence of PROCESS_TRACE_MODE_RAW_TIMESTAMP in LogFileMode.
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties
	pProperties := (C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&propertiesBuf[0]))
	pProperties.Wnode.BufferSize = C.ulong(bufSize)
	pProperties.Wnode.ClientContext = 1 // QPC for event Timestamp
	pProperties.Wnode.Flags = C.WNODE_FLAG_TRACED_GUID

	// Mark that we are going to process events in real time using a callback.
	pProperties.LogFileMode = C.EVENT_TRACE_REAL_TIME_MODE

	ret := C.StartTraceW(
		&s.hSession,
		C.LPWSTR(unsafe.Pointer(&s.etwSessionName[0])),
		pProperties,
	)
	switch err := windows.Errno(ret); err {
	case windows.ERROR_ALREADY_EXISTS:
		return ExistError{s.config.Name}
	case windows.ERROR_SUCCESS:
		s.propertiesBuf = propertiesBuf
		return nil
	default:
		return fmt.Errorf("StartTrace failed; %w", err)
	}
}

// subscribeToProvider wraps EnableTraceEx2.
func (s *Session) subscribeToProvider() error {
	// https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session
	params := C.ENABLE_TRACE_PARAMETERS{
		Version: 2, // ENABLE_TRACE_PARAMETERS_VERSION_2
	}
	for _, p := range s.config.EnableProperties {
		params.EnableProperty |= C.ULONG(p)
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
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex2
	ret := C.EnableTraceEx2(
		s.hSession,
		(*C.GUID)(unsafe.Pointer(&s.guid)),
		C.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		C.UCHAR(s.config.Level),
		C.ULONGLONG(s.config.MatchAnyKeyword),
		C.ULONGLONG(s.config.MatchAllKeyword),
		0,       // Timeout set to zero to enable the trace asynchronously
		&params, //nolint:gocritic // TODO: dupSubExpr?? gocritic bug?
	)

	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return fmt.Errorf("EVENT_CONTROL_CODE_ENABLE_PROVIDER failed; %w", status)
	}
	return nil
}

func (s *Session) unsubscribeFromProvider() error {
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
		0,
		0,
		0,
		0,
		nil)
	status := windows.Errno(ret)
	switch status {
	case windows.ERROR_SUCCESS, windows.ERROR_NOT_FOUND:
		return nil
	}
	return status
}

func (s *Session) processEvents(callbackContextKey uintptr) error {
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-opentracew
	traceHandle := C.OpenTraceHelper(
		(C.LPWSTR)(unsafe.Pointer(&s.etwSessionName[0])),
		(C.PVOID)(callbackContextKey),
	)
	if C.INVALID_PROCESSTRACE_HANDLE == traceHandle {
		return fmt.Errorf("OpenTraceW failed; %w", windows.GetLastError())
	}

	// BLOCKS UNTIL CLOSED!
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-processtrace
	// ETW_APP_DECLSPEC_DEPRECATED ULONG WMIAPI ProcessTrace(
	// 	PTRACEHANDLE HandleArray,
	// 	ULONG        HandleCount,
	// 	LPFILETIME   StartTime,
	// 	LPFILETIME   EndTime
	// );
	ret := C.ProcessTrace(
		C.PTRACEHANDLE(&traceHandle),
		1,   // ^ Imagine we pass an array with 1 element here.
		nil, // Do not want to limit StartTime (default is from now).
		nil, // Do not want to limit EndTime.
	)
	switch status := windows.Errno(ret); status {
	case windows.ERROR_SUCCESS, windows.ERROR_CANCELLED:
		return nil // Cancelled is obviously ok when we block until closing.
	default:
		return fmt.Errorf("ProcessTrace failed; %w", status)
	}
}

func (s *Session) stopSession() error {
	// ULONG WMIAPI ControlTraceW(
	//  TRACEHANDLE             TraceHandle,
	//  LPCWSTR                 InstanceName,
	//  PEVENT_TRACE_PROPERTIES Properties,
	//  ULONG                   ControlCode
	// );
	ret := C.ControlTraceW(
		s.hSession,
		nil,
		(C.PEVENT_TRACE_PROPERTIES)(unsafe.Pointer(&s.propertiesBuf[0])),
		C.EVENT_TRACE_CONTROL_STOP)

	// If you receive ERROR_MORE_DATA when stopping the session, ETW will have
	// already stopped the session before generating this error.
	// https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-controltracew
	switch status := windows.Errno(ret); status {
	case windows.ERROR_MORE_DATA, windows.ERROR_SUCCESS:
		return nil
	default:
		return status
	}
}

func randomName() string {
	if g, err := windows.GenerateGUID(); err == nil {
		return g.String()
	}

	// should be almost impossible, right?
	rand.Seed(time.Now().UnixNano())
	const alph = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = alph[rand.Intn(len(alph))]
	}
	return string(b)
}

// We can't pass Go-land pointers to the C-world so we use a classical trick
// storing real pointers inside global map and passing to C "fake pointers"
// which are actually map keys.
//
//nolint:gochecknoglobals
var (
	sessions       sync.Map
	sessionCounter uintptr
)

// newCallbackKey stores a @ptr inside a global storage returning its' key.
// After use the key should be freed using `freeCallbackKey`.
func newCallbackKey(ptr *Session) uintptr {
	key := atomic.AddUintptr(&sessionCounter, 1)
	sessions.Store(key, ptr)

	return key
}

func freeCallbackKey(key uintptr) {
	sessions.Delete(key)
}

// handleEvent is exported to guarantee C calling convention (cdecl).
//
// The function should be defined here but would be linked and used inside
// C code in `session.c`.
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
		ThreadID:        uint32(header.ThreadId),
		ProcessID:       uint32(header.ProcessId),
		TimeStamp:       stampToTime(C.GetTimeStamp(header)),
		ProviderID:      windowsGUIDToGo(header.ProviderId),
		ActivityID:      windowsGUIDToGo(header.ActivityId),

		Flags:         uint16(header.Flags),
		KernelTime:    uint32(C.GetKernelTime(header)),
		UserTime:      uint32(C.GetUserTime(header)),
		ProcessorTime: uint64(C.GetProcessorTime(header)),
	}
}

// eventDescriptorToGo converts windows EVENT_DESCRIPTOR to go structure.
func eventDescriptorToGo(descriptor C.EVENT_DESCRIPTOR) EventDescriptor {
	return EventDescriptor{
		ID:      uint16(descriptor.Id),
		Version: uint8(descriptor.Version),
		Channel: uint8(descriptor.Channel),
		Level:   uint8(descriptor.Level),
		OpCode:  uint8(descriptor.Opcode),
		Task:    uint16(descriptor.Task),
		Keyword: uint64(descriptor.Keyword),
	}
}
