package tracing_session

/*

#include "session.h"
*/
import "C"
import (
	"github.com/davecgh/go-spew/spew"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

var (
	api32 = windows.NewLazySystemDLL("Advapi32.dll")
)

var procEnableTraceEx2 = api32.NewProc("EnableTraceEx2")

const EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
const TRACE_LEVEL_VERBOSE = 5

func CreateSession(sessionName string) error { return nil }

func SubscribeSessionToProvider(sessionName string, providerGUID []byte) error { return nil }

func StartSession() error { return nil }

func StopSession() error { return nil }

type Session struct {
	hSession* C.TRACEHANDLE
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

func HandleEvent(event C.PEVENT_RECORD) {
	spew.Dump(event)
}

func (s *Session) StartSession() error {
	var trace C.EVENT_TRACE_LOGFILE
	trace.LogFileName = nil
	trace.LoggerName = C.CString(s.Name);
	trace.CurrentTime = 0
	trace.BuffersRead = 0
	trace.BufferSize = 0
	trace.Filled = 0
	trace.EventsLost = 0
	trace.Context = nil
	trace.LogFileMode = C.PROCESS_TRACE_MODE_REAL_TIME | C.PROCESS_TRACE_MODE_EVENT_RECORD
	trace.EventCallback = HandleEvent
	spew.Dump(trace)

	//hTrace := C.OpenTrace(&trace)
	//spew.Dump(hTrace)
	return nil
}
