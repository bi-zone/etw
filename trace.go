package tracing_session

/*
#cgo LDFLAGS: -ltdh

#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7

#include "session.h"


*/
import "C"
import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
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
	C.EnableTraceEx2(
		s.hSession,
		(*C.GUID)(unsafe.Pointer(&guid)),
		EVENT_CONTROL_CODE_ENABLE_PROVIDER,
		TRACE_LEVEL_VERBOSE,
		0, // TODO filters
		0,
		0,
		nil)
	return nil
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

func (s *Session) Error() chan error {
	return s.errChan
}

func (s *Session) Event() chan *Event {
	return s.eventChan
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

var (
	tdh               = windows.NewLazySystemDLL("Tdh.dll")
	tdhFormatProperty = tdh.NewProc("TdhFormatProperty")
)

// Go-analog of EVENT_RECORD structure.
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record
type Event struct {
	EventHeader EventHeader
	Properties  map[string]interface{}
}

type EventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       time.Time
	EventDescriptor EventDescriptor
	GUID            windows.GUID
	ActivityId      windows.GUID
}

type EventDescriptor struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	OpCode  uint8
	Task    uint16
	Keyword uint64
}

// https://docs.microsoft.com/ru-ru/windows/win32/etw/using-tdhformatproperty-to-consume-event-data
// https://github.com/microsoft/perfview/blob/master/src/TraceEvent/TraceEvent.cs
// https://docs.microsoft.com/en-us/windows/win32/etw/retrieving-event-metadata
func parseEvent(eventRecord C.PEVENT_RECORD) (*Event, error) {
	var event Event

	if eventRecord.EventHeader.Flags == C.EVENT_HEADER_FLAG_STRING_ONLY {
		event.Properties[""] = C.GoString((*C.char)(eventRecord.UserData))
		return &event, nil
	}

	pInfo, err := getEventInformation(eventRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to get event information witn %s", err)
	}

	event.EventHeader.EventDescriptor.Id = uint16(eventRecord.EventHeader.EventDescriptor.Id)

	parser := newEventParser(
		eventRecord,
		pInfo,
		uintptr(eventRecord.UserData),
		uintptr(eventRecord.UserData)+uintptr(eventRecord.UserDataLength))

	event.Properties = make(map[string]interface{}, int(pInfo.TopLevelPropertyCount))

	for i := 0; i < int(pInfo.TopLevelPropertyCount); i++ {
		name := parser.getPropertyName(i)
		value, err := parser.getPropertyValue(i)
		if err != nil {
			spew.Dump(err) // TODO make error channel
			continue
		}

		event.Properties[name] = value
	}

	return &event, nil
}

// eventParser is used for parsing raw windows structure.
type eventParser struct {
	record  C.PEVENT_RECORD
	info    C.PTRACE_EVENT_INFO
	data    uintptr
	endData uintptr
}

func newEventParser(r C.PEVENT_RECORD, info C.PTRACE_EVENT_INFO, data uintptr, endData uintptr) *eventParser {
	return &eventParser{
		record:  r,
		info:    info,
		data:    data,
		endData: endData,
	}
}

// getPropertyValue parsers property value. You should call getPropertyValue
// function in an incrementing index only (i = 0, 1, 2 ..). For the correct
// parsing property value data pointer should point to the right memory.
// eventParses controls data pointer with each GetPropertyValue call.
func (p *eventParser) getPropertyValue(i int) (string, error) {
	mapInfo, _ := getMapInfo(p.record, p.info, i)

	var pMapInfo uintptr
	if len(mapInfo) == 0 {
		pMapInfo = uintptr(0)
	} else {
		pMapInfo = uintptr(unsafe.Pointer(&mapInfo[0]))
	}

	var propertyLength C.int
	status := C.GetPropertyLength(p.record, p.info, C.int(i), &propertyLength)

	if status != 0 {
		return "", fmt.Errorf("failed to get property length with %v", status)
	}

	var formattedDataSize C.int
	var userDataConsumed C.int

	_, _, _ = tdhFormatProperty.Call(
		uintptr(unsafe.Pointer(p.record)),
		pMapInfo,
		uintptr(8),
		uintptr(C.GetInType(p.info, C.int(i))),
		uintptr(C.GetOutType(p.info, C.int(i))),
		uintptr(propertyLength),
		p.endData-p.data,
		uintptr(p.data),
		uintptr(unsafe.Pointer(&formattedDataSize)),
		0,
		uintptr(unsafe.Pointer(&userDataConsumed)),
	)

	if int(formattedDataSize) == 0 {
		return "", nil
	}

	formattedData := make([]byte, int(formattedDataSize))

	_, _, _ = tdhFormatProperty.Call(
		uintptr(unsafe.Pointer(p.info)),
		pMapInfo,
		uintptr(8),
		uintptr(C.GetInType(p.info, C.int(i))),
		uintptr(C.GetOutType(p.info, C.int(i))),
		uintptr(propertyLength),
		p.endData-p.data,
		uintptr(p.data),
		uintptr(unsafe.Pointer(&formattedDataSize)),
		uintptr(unsafe.Pointer(&formattedData[0])),
		uintptr(unsafe.Pointer(&userDataConsumed)),
	)

	p.data += uintptr(userDataConsumed)

	return createUTF16String(uintptr(unsafe.Pointer(&formattedData[0])), int(formattedDataSize)), nil
}

func (p *eventParser) getPropertyName(i int) string {
	propertyName := uintptr(C.GetPropertyName(p.info, C.int(i)))
	len := C.wcslen((C.PWCHAR)(unsafe.Pointer(propertyName)))
	return createUTF16String(propertyName, int(len))
}

func getMapInfo(event C.PEVENT_RECORD, info C.PTRACE_EVENT_INFO, index int) ([]byte, error) {
	var mapSize C.ulong

	mapName := C.GetMapName(info, C.int(index))

	status := C.TdhGetEventMapInformation(event, mapName, nil, &mapSize)

	if status == 1168 {
		return nil, nil
	}

	if status != 122 {
		return nil, fmt.Errorf("failed to get mapInfo with %v", status)
	}

	mapInfo := make([]byte, int(mapSize))
	status = C.TdhGetEventMapInformation(
		event,
		C.GetMapName(info, C.int(index)),
		(C.PEVENT_MAP_INFO)(unsafe.Pointer(&mapInfo[0])),
		&mapSize)
	if status != 0 {
		return nil, fmt.Errorf("failed to get mapInfo with %v", status)
	}
	return mapInfo, nil
}

func getProperty(event C.PEVENT_RECORD, info C.PTRACE_EVENT_INFO, index int) (interface{}, error) {
	var DataDescriptor C.PROPERTY_DATA_DESCRIPTOR

	DataDescriptor.PropertyName = C.GetPropertyName(info, C.int(index))

	// We don't parse structures yet.
	// In feature use getPropertyCount function to parse structures.
	DataDescriptor.ArrayIndex = C.ulong(0)

	var propertySize C.ulong

	status := C.TdhGetPropertySize(event, 0, nil, 1, &DataDescriptor, &propertySize)

	fmt.Println("Actual length", propertySize)

	if status != 0 {
		return nil, fmt.Errorf("failed to get property size")
	}

	rawData := make([]byte, int(propertySize))
	status = C.TdhGetProperty(
		event,
		0,
		nil,
		1,
		&DataDescriptor,
		propertySize,
		(*C.uchar)(unsafe.Pointer(&rawData[0])))

	propertyValue := formatData(event,
		C.GetInType(info, C.int(index)),
		C.GetOutType(info, C.int(index)),
		rawData,
		propertySize)

	return propertyValue, nil
}

func getPropertyCount(info C.PTRACE_EVENT_INFO, index int) int {
	return int(C.GetPropertyCount(info, C.int(index)))
}

func getEventInformation(pEvent C.PEVENT_RECORD) (C.PTRACE_EVENT_INFO, error) {
	var pInfo C.PTRACE_EVENT_INFO
	var bufferSize C.ulong

	// get structure size
	status := C.TdhGetEventInformation(pEvent, 0, nil, pInfo, &bufferSize)

	if C.ERROR_INSUFFICIENT_BUFFER == status {
		pInfo = C.PTRACE_EVENT_INFO(C.malloc(C.ulonglong(bufferSize)))
		if pInfo == nil {
			return nil, fmt.Errorf("failed to allocate memory for event info (size=%v)", bufferSize)
		}

		status = C.TdhGetEventInformation(pEvent, 0, nil, pInfo, &bufferSize)
	}
	if C.ERROR_SUCCESS != status {
		return nil, fmt.Errorf("TdhGetEventInformation failed with %v", status)
	}
	return pInfo, nil
}

func formatData(pEvent C.PEVENT_RECORD, InType C.USHORT, OutType C.USHORT, pData []byte, DataSize C.ulong) interface{} {
	switch InType {
	case TDH_INTYPE_UNICODESTRING:
		len := C.wcslen((C.PWCHAR)(unsafe.Pointer(&pData[0])))
		return createUTF16String(uintptr(unsafe.Pointer(&pData[0])), int(len))

	case TDH_INTYPE_COUNTEDSTRING:
		len := (int(pData[1]) << 8) & int(pData[0])
		return createUTF16String(uintptr(unsafe.Pointer(&pData[0])), len)

	case TDH_INTYPE_REVERSEDCOUNTEDSTRING:
		len := (int(pData[0]) << 8) & int(pData[1])
		return createUTF16String(uintptr(unsafe.Pointer(&pData[0])), len)

	case TDH_INTYPE_NONNULLTERMINATEDSTRING:
		len := int(DataSize)
		return createUTF16String(uintptr(unsafe.Pointer(&pData[0])), len)

	case TDH_INTYPE_ANSISTRING:
		len := C.strlen((*C.CHAR)(unsafe.Pointer(&pData[0])))
		return C.GoStringN((*C.CHAR)(unsafe.Pointer(&pData[0])), C.int(len))

	case TDH_INTYPE_COUNTEDANSISTRING:
		len := (int(pData[1]) << 8) & int(pData[0])
		return C.GoStringN((*C.CHAR)(unsafe.Pointer(&pData[0])), C.int(len))

	case TDH_INTYPE_REVERSEDCOUNTEDANSISTRING:
		len := (int(pData[0]) << 8) & int(pData[1])
		return C.GoStringN((*C.CHAR)(unsafe.Pointer(&pData[0])), C.int(len))

	case TDH_INTYPE_NONNULLTERMINATEDANSISTRING:
		len := int(DataSize)
		return C.GoStringN((*C.CHAR)(unsafe.Pointer(&pData[0])), C.int(len))

	case TDH_INTYPE_INT8:
		return int(pData[0])
	case TDH_INTYPE_UINT8:
		return uint(pData[0])
	case TDH_INTYPE_INT16:
		return int((uint(pData[1]) << 8) & uint(pData[0]))
	case TDH_INTYPE_UINT16:
		return (uint(pData[1]) << 8) & uint(pData[0])
	case TDH_INTYPE_INT32:
		return int32(binary.BigEndian.Uint32(pData[:4]))
	case TDH_INTYPE_UINT32:
		return binary.BigEndian.Uint32(pData[:4])
	case TDH_INTYPE_INT64:
		return int64(binary.BigEndian.Uint64(pData[:8]))
	case TDH_INTYPE_UINT64:
		return binary.BigEndian.Uint64(pData[:8])
	case TDH_INTYPE_FLOAT:
	case TDH_INTYPE_DOUBLE:
	case TDH_INTYPE_BOOLEAN:
		if pData[0] == 0 {
			return false
		}
		return true
	case TDH_INTYPE_BINARY:
		return pData
	case TDH_INTYPE_GUID:
	case TDH_INTYPE_POINTER:
	case TDH_INTYPE_SIZET:
	case TDH_INTYPE_FILETIME:
	case TDH_INTYPE_SYSTEMTIME:
	case TDH_INTYPE_SID:
	case TDH_INTYPE_HEXINT32:
	case TDH_INTYPE_HEXINT64:
	case TDH_INTYPE_UNICODECHAR:
	case TDH_INTYPE_ANSICHAR:
	case TDH_INTYPE_WBEMSID:
	default:
		return "WHATT"
	}
	return ""
}

// Creates UTF16 string from raw parts.
//
// Actually in go with has no way to make a slice from raw parts, ref:
// - https://github.com/golang/go/issues/13656
// - https://github.com/golang/go/issues/19367
// So the recommended way is "a fake cast" to the array with maximal len
// with a following slicing.
// Ref: https://github.com/golang/go/wiki/cgo#turning-c-arrays-into-go-slices
func createUTF16String(ptr uintptr, len int) string {
	if len == 0 {
		return ""
	}
	bytes := (*[1 << 29]uint16)(unsafe.Pointer(ptr))[:len:len]
	return syscall.UTF16ToString(bytes)
}

// windows constants
const (
	TDH_INTYPE_NULL = iota
	TDH_INTYPE_UNICODESTRING
	TDH_INTYPE_ANSISTRING
	TDH_INTYPE_INT8
	TDH_INTYPE_UINT8
	TDH_INTYPE_INT16
	TDH_INTYPE_UINT16
	TDH_INTYPE_INT32
	TDH_INTYPE_UINT32
	TDH_INTYPE_INT64
	TDH_INTYPE_UINT64
	TDH_INTYPE_FLOAT
	TDH_INTYPE_DOUBLE
	TDH_INTYPE_BOOLEAN
	TDH_INTYPE_BINARY
	TDH_INTYPE_GUID
	TDH_INTYPE_POINTER
	TDH_INTYPE_FILETIME
	TDH_INTYPE_SYSTEMTIME
	TDH_INTYPE_SID
	TDH_INTYPE_HEXINT32
	TDH_INTYPE_HEXINT64 // End of winmeta intypes.
)

const (
	TDH_INTYPE_COUNTEDSTRING = iota + 300 // Start of TDH intypes for WBEM.
	TDH_INTYPE_COUNTEDANSISTRING
	TDH_INTYPE_REVERSEDCOUNTEDSTRING
	TDH_INTYPE_REVERSEDCOUNTEDANSISTRING
	TDH_INTYPE_NONNULLTERMINATEDSTRING
	TDH_INTYPE_NONNULLTERMINATEDANSISTRING
	TDH_INTYPE_UNICODECHAR
	TDH_INTYPE_ANSICHAR
	TDH_INTYPE_SIZET
	TDH_INTYPE_HEXDUMP
	TDH_INTYPE_WBEMSID
)

const (
	EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
	TRACE_LEVEL_VERBOSE                = 5

	EVENT_TRACE_CONTROL_QUERY  = 0
	EVENT_TRACE_CONTROL_STOP   = 1
	EVENT_TRACE_CONTROL_UPDATE = 2

	ERROR_MORE_DATA = 234
)
