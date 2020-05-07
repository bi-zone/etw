package tracing_session

/*
#cgo LDFLAGS: -ltdh

#include "session.h"
*/
import "C"
import (
	"fmt"
	"math"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Event represents parsing result from structure:
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_record
type Event struct {
	Header      EventHeader
	eventRecord C.PEVENT_RECORD
}

// EventHeader consists common event information.
type EventHeader struct {
	EventDescriptor
	ThreadId   uint32
	ProcessId  uint32
	KernelTime uint32 // TODO: EVENT_HEADER_FLAG_NO_CPUTIME
	UserTime   uint32
	TimeStamp  time.Time
	ProviderID windows.GUID
	ActivityId windows.GUID
}

// EventDescriptor is Go-analog of EVENT_DESCRIPTOR structure.
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

func (e *Event) EventProperties() (map[string]interface{}, error) {
	if e.eventRecord.EventHeader.Flags == C.EVENT_HEADER_FLAG_STRING_ONLY {
		return map[string]interface{}{
			"_": C.GoString((*C.char)(e.eventRecord.UserData)),
		}, nil
	}

	p, err := newPropertyParser(e.eventRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to parse event properties; %s", err)
	}
	defer p.close()

	properties := make(map[string]interface{}, int(p.info.TopLevelPropertyCount))
	for i := 0; i < int(p.info.TopLevelPropertyCount); i++ {
		name := p.getPropertyName(i)
		value, err := p.getPropertyValue(i)
		if err != nil {
			// Parsing values we consume given event data buffer with var length chunks.
			// If we skip any -- we'll lost offset, so fail early.
			return nil, fmt.Errorf("failed to parse %q value %s", name, err)
		}
		properties[name] = value
	}
	return properties, nil
}

type ExtendedEventInfo struct {
	SessionId    *uint32
	ActivityId   *windows.GUID
	UserSID      *windows.SID
	InstanceInfo *EventInstanceInfo
	StackTrace   *EventStackTrace
}

type EventInstanceInfo struct {
	InstanceID       uint32
	ParentInstanceId uint32
	ParentGuid       windows.GUID
}

type EventStackTrace struct {
	MatchedID uint64
	Addresses []uint64
}

// ExtendedInfo parsers extended info from EVENT_RECORD structure.
func (e *Event) ExtendedInfo() ExtendedEventInfo {
	if e.eventRecord.EventHeader.Flags&C.EVENT_HEADER_FLAG_EXTENDED_INFO == 0 {
		return ExtendedEventInfo{}
	}
	return e.parseExtendedInfo()
}

func (e *Event) parseExtendedInfo() ExtendedEventInfo {
	var extendedData ExtendedEventInfo
	for i := 0; i < int(e.eventRecord.ExtendedDataCount); i++ {
		dataPtr := unsafe.Pointer(uintptr(C.GetDataPtr(e.eventRecord.ExtendedData, C.int(i))))

		switch C.GetExtType(e.eventRecord.ExtendedData, C.int(i)) {
		case C.EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID:
			cGUID := (C.LPGUID)(dataPtr)
			goGUID := windowsGuidToGo(*cGUID)
			extendedData.ActivityId = &goGUID

		case C.EVENT_HEADER_EXT_TYPE_SID:
			cSID := (*C.SID)(dataPtr)
			goSID, err := (*windows.SID)(unsafe.Pointer(cSID)).Copy()
			if err == nil {
				extendedData.UserSID = goSID
			}

		case C.EVENT_HEADER_EXT_TYPE_TS_ID:
			cSessionID := (C.PULONG)(dataPtr)
			goSessionID := uint32(*cSessionID)
			extendedData.SessionId = &goSessionID

		case C.EVENT_HEADER_EXT_TYPE_INSTANCE_INFO:
			instanceInfo := (C.PEVENT_EXTENDED_ITEM_INSTANCE)(dataPtr)
			extendedData.InstanceInfo = &EventInstanceInfo{
				InstanceID:       uint32(instanceInfo.InstanceId),
				ParentInstanceId: uint32(instanceInfo.ParentInstanceId),
				ParentGuid:       windowsGuidToGo(instanceInfo.ParentGuid),
			}

		case C.EVENT_HEADER_EXT_TYPE_STACK_TRACE32:
			stack32 := (C.PEVENT_EXTENDED_ITEM_STACK_TRACE32)(dataPtr)

			// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace32#remarks
			dataSize := C.GetDataSize(e.eventRecord.ExtendedData, C.int(i))
			matchedIDSize := unsafe.Sizeof(C.ULONG64(0))
			arraySize := (uintptr(dataSize) - matchedIDSize) / unsafe.Sizeof(C.ULONG(0))

			address := make([]uint64, arraySize)
			for j := 0; j < int(arraySize); j++ {
				address[j] = uint64(C.GetAddress32(stack32, C.int(j)))
			}

			extendedData.StackTrace = &EventStackTrace{
				MatchedID: uint64(stack32.MatchId),
				Addresses: address,
			}

		case C.EVENT_HEADER_EXT_TYPE_STACK_TRACE64:
			stack64 := (C.PEVENT_EXTENDED_ITEM_STACK_TRACE64)(dataPtr)

			// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_extended_item_stack_trace64#remarks
			dataSize := C.GetDataSize(e.eventRecord.ExtendedData, C.int(i))
			matchedIDSize := unsafe.Sizeof(C.ULONG64(0))
			arraySize := (uintptr(dataSize) - matchedIDSize) / unsafe.Sizeof(C.ULONG64(0))

			address := make([]uint64, arraySize)
			for j := 0; j < int(arraySize); j++ {
				address[j] = uint64(C.GetAddress64(stack64, C.int(j)))
			}

			extendedData.StackTrace = &EventStackTrace{
				MatchedID: uint64(stack64.MatchId),
				Addresses: address,
			}

			// TODO:
			// EVENT_HEADER_EXT_TYPE_PEBS_INDEX, EVENT_HEADER_EXT_TYPE_PMC_COUNTERS
			// EVENT_HEADER_EXT_TYPE_PSM_KEY, EVENT_HEADER_EXT_TYPE_EVENT_KEY,
			// EVENT_HEADER_EXT_TYPE_PROCESS_START_KEY, EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL
			// EVENT_HEADER_EXT_TYPE_PROV_TRAITS
		}
	}
	return extendedData
}

func getEventInformation(pEvent C.PEVENT_RECORD) (C.PTRACE_EVENT_INFO, error) {
	var pInfo C.PTRACE_EVENT_INFO
	var bufferSize C.ulong

	// get structure size
	status := C.TdhGetEventInformation(pEvent, 0, nil, pInfo, &bufferSize)

	if windows.Errno(status) == windows.ERROR_INSUFFICIENT_BUFFER {
		pInfo = C.PTRACE_EVENT_INFO(C.malloc(C.ulonglong(bufferSize)))
		if pInfo == nil {
			return nil, fmt.Errorf("failed to allocate memory for event info (size=%v)", bufferSize)
		}

		status = C.TdhGetEventInformation(pEvent, 0, nil, pInfo, &bufferSize)
	}

	if windows.Errno(status) != windows.ERROR_SUCCESS {
		return nil, fmt.Errorf("TdhGetEventInformation failed with %v", status)
	}

	return pInfo, nil
}

// propertyParser is used for parsing properties from raw EVENT_RECORD structure.
type propertyParser struct {
	record  C.PEVENT_RECORD
	info    C.PTRACE_EVENT_INFO
	data    uintptr
	endData uintptr
}

func newPropertyParser(r C.PEVENT_RECORD) (*propertyParser, error) {
	info, err := getEventInformation(r)
	if err == nil {
		return &propertyParser{
			record:  r,
			info:    info,
			data:    uintptr(r.UserData),
			endData: uintptr(r.UserData) + uintptr(r.UserDataLength),
		}, nil
	}
	if info != nil {
		C.free(unsafe.Pointer(info))
	}
	return nil, fmt.Errorf("failed to get event information")
}

func (p *propertyParser) close() {
	if p.info != nil {
		C.free(unsafe.Pointer(p.info))
	}
}

func (p *propertyParser) getPropertyName(i int) string {
	propertyName := uintptr(C.GetPropertyName(p.info, C.int(i)))
	length := C.wcslen((C.PWCHAR)(unsafe.Pointer(propertyName)))
	return createUTF16String(propertyName, int(length))
}

// getPropertyValue parsers property value. You should call getPropertyValue
// function in an incrementing index only (i = 0, 1, 2 ..). For the correct
// parsing property value data pointer should point to the right memory.
// eventParses controls data pointer with each GetPropertyValue call.
func (p *propertyParser) getPropertyValue(i int) (interface{}, error) {
	if int(C.PropertyIsStruct(p.info, C.int(i))) == 1 {
		return p.parseComplexType(i)
	}
	return p.parseSimpleType(i)
}

// TODO: Return map[string]string
func (p *propertyParser) parseComplexType(i int) ([]string, error) {
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

var (
	tdh               = windows.NewLazySystemDLL("Tdh.dll")
	tdhFormatProperty = tdh.NewProc("TdhFormatProperty")
)

func (p *propertyParser) parseSimpleType(i int) (string, error) {
	mapInfo, err := getMapInfo(p.record, p.info, i)
	if err != nil {
		return "", fmt.Errorf("failed to get map info; %s", err)
	}

	var pMapInfo uintptr
	if len(mapInfo) == 0 {
		pMapInfo = uintptr(unsafe.Pointer(nil))
	} else {
		pMapInfo = uintptr(unsafe.Pointer(&mapInfo[0]))
	}

	var propertyLength C.uint
	status := C.GetPropertyLength(p.record, p.info, C.int(i), &propertyLength)
	if windows.Errno(status) != windows.ERROR_SUCCESS {
		return "", fmt.Errorf("failed to get property length with %v", status)
	}

	var formattedDataSize C.int
	var userDataConsumed C.int
	// We make the first call to get the size of formatted data.
	r0, _, _ := tdhFormatProperty.Call(
		uintptr(unsafe.Pointer(p.record)),
		pMapInfo,
		uintptr(strconv.IntSize/8),
		uintptr(C.GetInType(p.info, C.int(i))),
		uintptr(C.GetOutType(p.info, C.int(i))),
		uintptr(propertyLength),
		p.endData-p.data,
		p.data,
		uintptr(unsafe.Pointer(&formattedDataSize)),
		0,
		uintptr(unsafe.Pointer(&userDataConsumed)),
	)

	if windows.Errno(r0) != windows.ERROR_INSUFFICIENT_BUFFER {
		return "", fmt.Errorf("failed to format event property with %v", r0)
	}

	if int(formattedDataSize) == 0 {
		return "", nil
	}

	formattedData := make([]byte, int(formattedDataSize))

	r0, _, _ = tdhFormatProperty.Call(
		uintptr(unsafe.Pointer(p.info)),
		pMapInfo,
		uintptr(strconv.IntSize/8),
		uintptr(C.GetInType(p.info, C.int(i))),
		uintptr(C.GetOutType(p.info, C.int(i))),
		uintptr(propertyLength),
		p.endData-p.data,
		p.data,
		uintptr(unsafe.Pointer(&formattedDataSize)),
		uintptr(unsafe.Pointer(&formattedData[0])),
		uintptr(unsafe.Pointer(&userDataConsumed)),
	)

	if windows.Errno(r0) != windows.ERROR_SUCCESS {
		return "", fmt.Errorf("failed to format event property with %v", r0)
	}

	p.data += uintptr(userDataConsumed)

	return createUTF16String(uintptr(unsafe.Pointer(&formattedData[0])), int(formattedDataSize)), nil
}

func getMapInfo(event C.PEVENT_RECORD, info C.PTRACE_EVENT_INFO, index int) ([]byte, error) {
	var mapSize C.ulong
	mapName := C.GetMapName(info, C.int(index))
	status := C.TdhGetEventMapInformation(event, mapName, nil, &mapSize)

	if windows.Errno(status) == windows.ERROR_NOT_FOUND {
		return nil, nil
	}

	if windows.Errno(status) != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, fmt.Errorf("failed to get mapInfo with %v", status)
	}

	mapInfo := make([]byte, int(mapSize))
	status = C.TdhGetEventMapInformation(
		event,
		C.GetMapName(info, C.int(index)),
		(C.PEVENT_MAP_INFO)(unsafe.Pointer(&mapInfo[0])),
		&mapSize)

	if windows.Errno(status) != windows.ERROR_SUCCESS {
		return nil, fmt.Errorf("failed to get mapInfo with %v", status)
	}

	return mapInfo, nil
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

// stampToTime translates FileTime to a golang time. Same as in standard packages.
func stampToTime(quadPart C.LONGLONG) time.Time {
	ft := windows.Filetime{
		HighDateTime: uint32(quadPart >> 32),
		LowDateTime:  uint32(quadPart & math.MaxUint32),
	}
	return time.Unix(0, ft.Nanoseconds())
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
	return windows.UTF16ToString(bytes)
}
