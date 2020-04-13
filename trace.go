package tracing_session

/*
#cgo LDFLAGS: -ltdh

#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7

#include "session.h"
#include "Sddl.h" // for sid converting


*/
import "C"
import (
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
	EventHeader  EventHeader
	ExtendedData map[string]interface{}
	Properties   map[string]interface{}
}

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

func parseEvent(eventRecord C.PEVENT_RECORD) (*Event, error) {
	var event Event

	if eventRecord.EventHeader.Flags == C.EVENT_HEADER_FLAG_STRING_ONLY {
		event.Properties[""] = C.GoString((*C.char)(eventRecord.UserData))
		return &event, nil
	}

	info, err := getEventInformation(eventRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to get event information witn %s", err)
	}

	parser := newEventParser(
		eventRecord,
		info,
		uintptr(eventRecord.UserData),
		uintptr(eventRecord.UserData)+uintptr(eventRecord.UserDataLength))

	event.ExtendedData = parser.parseExtendedInfo()
	event.EventHeader = parser.parseEventHeader()
	event.Properties = make(map[string]interface{}, int(info.TopLevelPropertyCount))

	for i := 0; i < int(info.TopLevelPropertyCount); i++ {
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

func (p *eventParser) parseExtendedInfo() map[string]interface{} {
	extendedData := make(map[string]interface{}, int(p.record.ExtendedDataCount))

	for i := 0; i < int(p.record.ExtendedDataCount); i++ {
		dataPtr := unsafe.Pointer(uintptr(C.GetDataPtr(p.record.ExtendedData, C.int(i))))

		switch C.GetExtType(p.record.ExtendedData, C.int(i)) {
		case EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID:
			cGUID := (C.LPGUID)(dataPtr)
			extendedData["ActivityId"] = windowsGuidToGo(*cGUID)

		case EVENT_HEADER_EXT_TYPE_SID:
			cSID := (C.PISID)(dataPtr)
			sid := make([]byte, 50)
			C.ConvertSidToStringSidA((C.PVOID)(cSID), (*C.LPSTR)(unsafe.Pointer(&sid[0])))
			extendedData["UserID"] = string(sid)

		case EVENT_HEADER_EXT_TYPE_TS_ID:
			cSessionID := (C.PULONG)(dataPtr)
			extendedData["SessionId"] = uint32(*cSessionID)

		case EVENT_HEADER_EXT_TYPE_INSTANCE_INFO:
			instanceInfo := (C.PEVENT_EXTENDED_ITEM_INSTANCE)(dataPtr)
			extendedData["InstanceInfo"] = map[string]interface{}{
				"InstanceID":       uint32(instanceInfo.InstanceId),
				"ParentInstanceId": uint32(instanceInfo.ParentInstanceId),
				"ParentGuid":       windowsGuidToGo(instanceInfo.ParentGuid),
			}

		case EVENT_HEADER_EXT_TYPE_STACK_TRACE32:
			stack32 := (C.PEVENT_EXTENDED_ITEM_STACK_TRACE32)(dataPtr)
			arraySize := (int(C.GetDataSize(p.record.ExtendedData, C.int(i))) - 8) / 4

			address := make([]uint32, arraySize)
			for j := 0; j < arraySize; j++ {
				address[j] = uint32(C.GetAddress32(stack32, C.int(j)))
			}

			extendedData["StackTrace32"] = map[string]interface{}{
				"MatchedID": uint64(stack32.MatchId),
				"Address":   address,
			}

		case EVENT_HEADER_EXT_TYPE_STACK_TRACE64:
			stack64 := (C.PEVENT_EXTENDED_ITEM_STACK_TRACE64)(dataPtr)
			arraySize := (int(C.GetDataSize(p.record.ExtendedData, C.int(i))) - 8) / 8

			address := make([]uint64, arraySize)
			for j := 0; j < arraySize; j++ {
				address[j] = uint64(C.GetAddress64(stack64, C.int(j)))
			}

			extendedData["StackTrace64"] = map[string]interface{}{
				"MatchedID": uint64(stack64.MatchId),
				"Address":   address,
			}
		case EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL:
		case EVENT_HEADER_EXT_TYPE_PROV_TRAITS:
		}
	}

	return extendedData
}

func (p *eventParser) parseEventHeader() EventHeader {
	return EventHeader{
		ThreadId:        uint32(p.record.EventHeader.ThreadId),
		ProcessId:       uint32(p.record.EventHeader.ProcessId),
		TimeStamp:       p.parseTimestamp(),
		EventDescriptor: p.getEventDescriptor(),
		ProviderID:      windowsGuidToGo(p.record.EventHeader.ProviderId),
		KernelTime:      uint32(C.GetKernelTime(p.record.EventHeader)),
		UserTime:        uint32(C.GetUserTime(p.record.EventHeader)),
		ActivityId:      windowsGuidToGo(p.record.EventHeader.ActivityId),
	}
}

func windowsGuidToGo(guid C.GUID) windows.GUID {
	var data4 [8]byte
	for i := range data4 {
		data4[i] = byte(guid.Data4[i])
	}

	return windows.GUID{
		Data1: uint32(guid.Data1),
		Data2: uint16(guid.Data2),
		Data3: uint16(guid.Data3),
		Data4: data4,
	}
}

func (p *eventParser) parseTimestamp() time.Time {
	stamp := uint64(C.GetTimeStamp(p.record))

	stamp -= 116444736000000000
	stamp *= 100
	return time.Unix(0, int64(stamp)).UTC()
}

func (p *eventParser) getEventDescriptor() EventDescriptor {
	return EventDescriptor{
		Id:      uint16(p.record.EventHeader.EventDescriptor.Id),
		Version: uint8(p.record.EventHeader.EventDescriptor.Version),
		Channel: uint8(p.record.EventHeader.EventDescriptor.Channel),
		Level:   uint8(p.record.EventHeader.EventDescriptor.Level),
		OpCode:  uint8(p.record.EventHeader.EventDescriptor.Opcode),
		Task:    uint16(p.record.EventHeader.EventDescriptor.Task),
		Keyword: uint64(p.record.EventHeader.EventDescriptor.Keyword),
	}
}

// getPropertyValue parsers property value. You should call getPropertyValue
// function in an incrementing index only (i = 0, 1, 2 ..). For the correct
// parsing property value data pointer should point to the right memory.
// eventParses controls data pointer with each GetPropertyValue call.
func (p *eventParser) getPropertyValue(i int) (interface{}, error) {
	if p.propertyIsStructure(i) {
		return p.parseComplexType(i)
	}
	return p.parseSimpleType(i)
}

func (p *eventParser) getPropertyName(i int) string {
	propertyName := uintptr(C.GetPropertyName(p.info, C.int(i)))
	length := C.wcslen((C.PWCHAR)(unsafe.Pointer(propertyName)))
	return createUTF16String(propertyName, int(length))
}

func (p *eventParser) propertyIsStructure(i int) bool {
	if int(C.PropertyIsStruct(p.info, C.int(i))) == 1 {
		return true
	}
	return false
}

func (p *eventParser) parseComplexType(i int) ([]string, error) {
	startIndex := int(C.GetStartIndex(p.info, C.int(i)))
	lastIndex := int(C.GetLastIndex(p.info, C.int(i)))

	structure := make([]string, lastIndex-startIndex)
	for j := startIndex; j < lastIndex; j++ {
		value, err := p.parseSimpleType(j)
		if err != nil {
			return nil, fmt.Errorf("failed parse field of complex property type; %s", err)
		}
		structure[j-startIndex] = value
	}
	return structure, nil
}

func (p *eventParser) parseSimpleType(i int) (string, error) {
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
	EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
	TRACE_LEVEL_VERBOSE                = 5

	EVENT_TRACE_CONTROL_QUERY  = 0
	EVENT_TRACE_CONTROL_STOP   = 1
	EVENT_TRACE_CONTROL_UPDATE = 2

	ERROR_MORE_DATA = 234
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
