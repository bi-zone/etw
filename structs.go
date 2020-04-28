package tracing_session

/*
#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7

#include "session.h"
*/
import "C"
import (
	"time"

	"golang.org/x/sys/windows"
)

type Session struct {
	hSession   C.TRACEHANDLE
	properties C.PEVENT_TRACE_PROPERTIES
	Name       string

	errChan   chan error
	eventChan chan *Event
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

// windows constants

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

const (
	TRACE_LEVEL_VERBOSE = 5
)

const (
	EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
)

const (
	EVENT_TRACE_CONTROL_QUERY  = 0
	EVENT_TRACE_CONTROL_STOP   = 1
	EVENT_TRACE_CONTROL_UPDATE = 2
)

const (
	EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID = iota + 1
	EVENT_HEADER_EXT_TYPE_SID
	EVENT_HEADER_EXT_TYPE_TS_ID
	EVENT_HEADER_EXT_TYPE_INSTANCE_INFO
	EVENT_HEADER_EXT_TYPE_STACK_TRACE32
	EVENT_HEADER_EXT_TYPE_STACK_TRACE64
	EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL
	EVENT_HEADER_EXT_TYPE_PROV_TRAITS
)
