//+build windows

// Package etw allows you to receive Event Tracing for Windows (ETW) events.
//
// etw allows you to process events from new TraceLogging providers as well as
// from classic (aka EventLog) providers, so you could actually listen to
// anything you can see in Event Viewer window.
//
// For possible usage examples take a look at
// https://github.com/bi-zone/etw/tree/master/examples
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

// ExistsError is returned by NewSession if the session name is already taken.
//
// Having ExistsError you have an option to force kill the session:
//
//		var exists etw.ExistsError
//		s, err = etw.NewSession(s.guid, etw.WithName(sessionName))
//		if errors.As(err, &exists) {
//			err = etw.KillSession(exists.SessionName)
//		}
//
type ExistsError struct{ SessionName string }

func (e ExistsError) Error() string {
	return fmt.Sprintf("session %q already exist", e.SessionName)
}

// Session represents a Windows event tracing session that is ready to start
// events processing. Session subscribes to the given ETW provider only on
// `.Process`  call, so having a Session without `.Process` called should not
// affect OS performance.
//
// Session should be closed via `.Close` call to free obtained OS resources
// even if `.Process` has never been called.
type Session struct {
	guid     windows.GUID
	config   SessionOptions
	callback EventCallback

	etwSessionName []uint16
	hSession       C.TRACEHANDLE
	propertiesBuf  []byte
}

// EventCallback is any function that could handle an ETW event. EventCallback
// is called synchronously and sequentially on every event received by Session
// one by one.
//
// If EventCallback can't handle all ETW events produced, OS will handle a
// tricky file-based cache for you, however, it's recommended not to perform
// long-running tasks inside a callback.
//
// N.B. Event pointer @e is valid ONLY inside a callback. You CAN'T copy a
// whole event, only EventHeader, EventProperties and ExtendedEventInfo
// separately.
type EventCallback func(e *Event)

// NewSession creates a Windows event tracing session instance. Session with no
// options provided is a usable session, but it could be a bit noisy. It's
// recommended to refine the session with level and match keywords options
// to get rid of unnecessary events.
//
// You MUST call `.Close` on session after use to clear associated resources,
// otherwise it will leak in OS internals until system reboot.
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

	if err := s.createETWSession(); err != nil {
		return nil, fmt.Errorf("failed to create session; %w", err)
	}
	// TODO: consider setting a finalizer with .Close

	return &s, nil
}

// Process starts processing of ETW events. Events will be passed to @cb
// synchronously and sequentially. Take a look to EventCallback documentation
// for more info about events processing.
//
// N.B. Process blocks until `.Close` being called!
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

// UpdateOptions changes subscription parameters in runtime. The only option
// that can't be updated is session name. To change session name -- stop and
// recreate a session with new desired name.
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

// KillSession forces the session with a given @name to stop. Don't having a
// session handle we can't shutdown it gracefully unsubscribing from all the
// providers first, so we just stop the session itself.
//
// Use KillSession only to destroy session you've lost control over. If you
// have a session handle always prefer `.Close`.
func KillSession(name string) error {
	nameUTF16, err := windows.UTF16FromString(name)
	if err != nil {
		return fmt.Errorf("failed to convert session name to utf16; %w", err)
	}
	sessionNameLength := len(nameUTF16) * int(unsafe.Sizeof(nameUTF16[0]))

	//
	// For a graceful shutdown we should unsubscribe from all providers associated
	// with the session, but we can't find a way to query them using WinAPI.
	// So we just ask the session to stop and hope that wont hurt anything too bad.
	//

	// We don't know if this session was opened with the log file or not
	// (session could be opened without our library) so allocate memory for LogFile name too.
	const maxLengthLogfileName = 1024
	bufSize := int(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{})) + sessionNameLength + maxLengthLogfileName
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

// createETWSession wraps StartTraceW.
func (s *Session) createETWSession() error {
	// We need to allocate a sequential buffer for a structure and a session name
	// which will be placed there by an API call (for the future calls).
	//
	// (Ref: https://docs.microsoft.com/en-us/windows/win32/etw/wnode-header#members)
	//
	// The only way to do it in go -- unsafe cast of the allocated memory.
	sessionNameSize := len(s.etwSessionName) * int(unsafe.Sizeof(s.etwSessionName[0]))
	bufSize := int(unsafe.Sizeof(C.EVENT_TRACE_PROPERTIES{})) + sessionNameSize
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
		return ExistsError{SessionName: s.config.Name}
	case windows.ERROR_SUCCESS:
		s.propertiesBuf = propertiesBuf
		return nil
	default:
		return fmt.Errorf("StartTraceW failed; %w", err)
	}
}

// subscribeToProvider wraps EnableTraceEx with IsEnabled being 1.
func (s *Session) subscribeToProvider() error {
	// https://docs.microsoft.com/en-us/windows/win32/etw/configuring-and-starting-an-event-tracing-session
	var enableProperty C.ULONG
	for _, p := range s.config.EnableProperties {
		enableProperty |= C.ULONG(p)
	}

	// ULONG WMIAPI EnableTraceEx(
	//	LPCGUID                  ProviderId,
	//	LPCGUID                  SourceId,
	//	TRACEHANDLE              TraceHandle,
	//	ULONG                    IsEnabled,
	//	UCHAR                    Level,
	//	ULONGLONG                MatchAnyKeyword,
	//	ULONGLONG                MatchAllKeyword,
	//	ULONG                    EnableProperty,
	//	PEVENT_FILTER_DESCRIPTOR EnableFilterDesc
	//);
	//
	// Ref: https://docs.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-enabletraceex
	ret := C.EnableTraceEx(
		(*C.GUID)(unsafe.Pointer(&s.guid)),
		nil,
		s.hSession,
		1,
		C.UCHAR(s.config.Level),
		C.ULONGLONG(s.config.MatchAnyKeyword),
		C.ULONGLONG(s.config.MatchAllKeyword),
		enableProperty,
		nil,
	)

	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return fmt.Errorf("EVENT_CONTROL_CODE_ENABLE_PROVIDER failed; %w", status)
	}
	return nil
}

// unsubscribeFromProvider wraps EnableTraceEx with IsEnabled being 0.
func (s *Session) unsubscribeFromProvider() error {
	// ULONG WMIAPI EnableTraceEx(
	//	LPCGUID                  ProviderId,
	//	LPCGUID                  SourceId,
	//	TRACEHANDLE              TraceHandle,
	//	ULONG                    IsEnabled,
	//	UCHAR                    Level,
	//	ULONGLONG                MatchAnyKeyword,
	//	ULONGLONG                MatchAllKeyword,
	//	ULONG                    EnableProperty,
	//	PEVENT_FILTER_DESCRIPTOR EnableFilterDesc
	//);
	ret := C.EnableTraceEx(
		(*C.GUID)(unsafe.Pointer(&s.guid)),
		nil,
		s.hSession,
		0,
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

// processEvents subscribes to the actual provider events and starts its processing.
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

// stopSession wraps ControlTraceW with EVENT_TRACE_CONTROL_STOP.
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

	evt := &Event{
		Header:      eventHeaderToGo(eventRecord.EventHeader),
		eventRecord: eventRecord,
	}
	targetSession.(*Session).callback(evt)
	evt.eventRecord = nil
}

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
