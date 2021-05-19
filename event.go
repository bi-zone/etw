//+build windows

package etw

/*
	#include "session.h"
*/
import "C"
import (
	"fmt"
	"math"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Event is a single event record received from ETW provider. The only thing
// that is parsed implicitly is an EventHeader (which just translated from C
// structures mostly 1:1), all other data are parsed on-demand.
//
// Events will be passed to the user EventCallback. It's invalid to use Event
// methods outside of an EventCallback.
type Event struct {
	Header      EventHeader
	eventRecord C.PEVENT_RECORD
}

// EventHeader contains an information that is common for every ETW event
// record.
//
// EventHeader fields is self-descriptive. If you need more info refer to the
// original struct docs:
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header
type EventHeader struct {
	EventDescriptor

	ThreadID  uint32
	ProcessID uint32
	TimeStamp time.Time

	ProviderID windows.GUID
	ActivityID windows.GUID

	Flags         uint16
	KernelTime    uint32
	UserTime      uint32
	ProcessorTime uint64
}

// HasCPUTime returns true if the event has separate UserTime and KernelTime
// measurements. Otherwise the value of UserTime and KernelTime is meaningless
// and you should use ProcessorTime instead.
func (h EventHeader) HasCPUTime() bool {
	switch {
	case h.Flags&C.EVENT_HEADER_FLAG_NO_CPUTIME != 0:
		return false
	case h.Flags&C.EVENT_HEADER_FLAG_PRIVATE_SESSION != 0:
		return false
	default:
		return true
	}
}

// EventDescriptor contains low-level metadata that defines received event.
// Most of fields could be used to refine events filtration.
//
// For detailed information about fields values refer to EVENT_DESCRIPTOR docs:
// https://docs.microsoft.com/ru-ru/windows/win32/api/evntprov/ns-evntprov-event_descriptor
type EventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	OpCode  uint8
	Task    uint16
	Keyword uint64
}

// EventProperties returns a map that represents events-specific data provided
// by event producer. Returned data depends on the provider, event type and even
// provider and event versions.
//
// The simplest (and the recommended) way to parse event data is to use TDH
// family of functions that render event data to the strings exactly as you can
// see it in the Event Viewer.
//
// EventProperties returns a map that could be interpreted as "structure that
// fit inside a map". Map keys is a event data field names, map values is field
// values rendered to strings. So map values could be one of the following:
//		- `[]string` for arrays of any types;
//		- `map[string]interface{}` for fields that are structures;
//		- `string` for any other values.
//
// Take a look at `TestParsing` for possible EventProperties values.
func (e *Event) EventProperties() (map[string]interface{}, error) {
	if e.eventRecord == nil {
		return nil, fmt.Errorf("usage of Event is invalid outside of EventCallback")
	}

	if e.eventRecord.EventHeader.Flags == C.EVENT_HEADER_FLAG_STRING_ONLY {
		return map[string]interface{}{
			"_": C.GoString((*C.char)(e.eventRecord.UserData)),
		}, nil
	}

	p, err := newPropertyParser(e.eventRecord)
	if err != nil {
		return nil, fmt.Errorf("failed to parse event properties; %w", err)
	}
	defer p.free()

	properties := make(map[string]interface{}, int(p.info.TopLevelPropertyCount))
	for i := 0; i < int(p.info.TopLevelPropertyCount); i++ {
		name := p.getPropertyName(i)
		value, err := p.getPropertyValue(i)
		if err != nil {
			// Parsing values we consume given event data buffer with var length chunks.
			// If we skip any -- we'll lost offset, so fail early.
			return nil, fmt.Errorf("failed to parse %q value; %w", name, err)
		}
		properties[name] = value
	}
	return properties, nil
}

// ExtendedEventInfo contains additional information about received event. All
// ExtendedEventInfo fields are optional and are nils being not set by provider.
//
// Presence of concrete fields is controlled by WithProperty option and an
// ability of event provider to set the required fields.
//
// More info about fields is available at EVENT_HEADER_EXTENDED_DATA_ITEM.ExtType
// documentation:
// https://docs.microsoft.com/en-us/windows/win32/api/evntcons/ns-evntcons-event_header_extended_data_item
type ExtendedEventInfo struct {
	SessionID    *uint32
	ActivityID   *windows.GUID
	UserSID      *windows.SID
	InstanceInfo *EventInstanceInfo
	StackTrace   *EventStackTrace
}

// EventInstanceInfo defines the relationship between events if its provided.
type EventInstanceInfo struct {
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGUID       windows.GUID
}

// EventStackTrace describes a call trace of the event occurred.
type EventStackTrace struct {
	MatchedID uint64
	Addresses []uint64
}

// ExtendedInfo extracts ExtendedEventInfo structure from native buffers of
// received event record.
//
// If no ExtendedEventInfo is available inside an event record function returns
// the structure with all fields set to nil.
func (e *Event) ExtendedInfo() ExtendedEventInfo {
	if e.eventRecord == nil { // Usage outside of event callback.
		return ExtendedEventInfo{}
	}
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
			goGUID := windowsGUIDToGo(*cGUID)
			extendedData.ActivityID = &goGUID

		case C.EVENT_HEADER_EXT_TYPE_SID:
			cSID := (*C.SID)(dataPtr)
			goSID, err := (*windows.SID)(unsafe.Pointer(cSID)).Copy()
			if err == nil {
				extendedData.UserSID = goSID
			}

		case C.EVENT_HEADER_EXT_TYPE_TS_ID:
			cSessionID := (C.PULONG)(dataPtr)
			goSessionID := uint32(*cSessionID)
			extendedData.SessionID = &goSessionID

		case C.EVENT_HEADER_EXT_TYPE_INSTANCE_INFO:
			instanceInfo := (C.PEVENT_EXTENDED_ITEM_INSTANCE)(dataPtr)
			extendedData.InstanceInfo = &EventInstanceInfo{
				InstanceID:       uint32(instanceInfo.InstanceId),
				ParentInstanceID: uint32(instanceInfo.ParentInstanceId),
				ParentGUID:       windowsGUIDToGo(instanceInfo.ParentGuid),
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

// propertyParser is used for parsing properties from raw EVENT_RECORD structure.
type propertyParser struct {
	record  C.PEVENT_RECORD
	info    C.PTRACE_EVENT_INFO
	data    uintptr
	endData uintptr
	ptrSize uintptr
}

func newPropertyParser(r C.PEVENT_RECORD) (*propertyParser, error) {
	info, err := getEventInformation(r)
	if err != nil {
		if info != nil {
			C.free(unsafe.Pointer(info))
		}
		return nil, fmt.Errorf("failed to get event information; %w", err)
	}
	ptrSize := unsafe.Sizeof(uint64(0))
	if r.EventHeader.Flags&C.EVENT_HEADER_FLAG_32_BIT_HEADER == C.EVENT_HEADER_FLAG_32_BIT_HEADER {
		ptrSize = unsafe.Sizeof(uint32(0))
	}
	return &propertyParser{
		record:  r,
		info:    info,
		ptrSize: ptrSize,
		data:    uintptr(r.UserData),
		endData: uintptr(r.UserData) + uintptr(r.UserDataLength),
	}, nil
}

// getEventInformation wraps TdhGetEventInformation. It extracts some kind of
// simplified event information used by Tdh* family of function.
//
// Returned info MUST be freed after use.
func getEventInformation(pEvent C.PEVENT_RECORD) (C.PTRACE_EVENT_INFO, error) {
	var (
		pInfo      C.PTRACE_EVENT_INFO
		bufferSize C.ulong
	)

	// Retrieve a buffer size.
	ret := C.TdhGetEventInformation(pEvent, 0, nil, pInfo, &bufferSize)
	if windows.Errno(ret) == windows.ERROR_INSUFFICIENT_BUFFER {
		pInfo = C.PTRACE_EVENT_INFO(C.malloc(C.size_t(bufferSize)))
		if pInfo == nil {
			return nil, fmt.Errorf("malloc(%v) failed", bufferSize)
		}

		// Fetch the buffer itself.
		ret = C.TdhGetEventInformation(pEvent, 0, nil, pInfo, &bufferSize)
	}

	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return pInfo, fmt.Errorf("TdhGetEventInformation failed; %w", status)
	}

	return pInfo, nil
}

// free frees associated PTRACE_EVENT_INFO if any assigned.
func (p *propertyParser) free() {
	if p.info != nil {
		C.free(unsafe.Pointer(p.info))
	}
}

// getPropertyName returns a name of the @i-th event property.
func (p *propertyParser) getPropertyName(i int) string {
	propertyName := uintptr(C.GetPropertyName(p.info, C.int(i)))
	length := C.wcslen((C.PWCHAR)(unsafe.Pointer(propertyName)))
	return createUTF16String(propertyName, int(length))
}

// getPropertyValue retrieves a value of @i-th property.
//
// N.B. getPropertyValue HIGHLY depends not only on @i but also on memory
// offsets, so check twice calling with non-sequential indexes.
func (p *propertyParser) getPropertyValue(i int) (interface{}, error) {
	var arraySizeC C.uint
	ret := C.GetArraySize(p.record, p.info, C.int(i), &arraySizeC)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return nil, fmt.Errorf("failed to get array size; %w", status)
	}

	arraySize := int(arraySizeC)
	result := make([]interface{}, arraySize)
	for j := 0; j < arraySize; j++ {
		var (
			value interface{}
			err   error
		)
		// Note that we pass same idx to parse function. Actual returned values are controlled
		// by data pointers offsets.
		if int(C.PropertyIsStruct(p.info, C.int(i))) == 1 {
			value, err = p.parseStruct(i)
		} else {
			value, err = p.parseSimpleType(i)
		}
		if err != nil {
			return nil, err
		}
		result[j] = value
	}

	if int(C.PropertyIsArray(p.info, C.int(i))) == 1 {
		return result, nil
	}
	return result[0], nil
}

// parseStruct tries to extract fields of embedded structure at property @i.
func (p *propertyParser) parseStruct(i int) (map[string]interface{}, error) {
	startIndex := int(C.GetStructStartIndex(p.info, C.int(i)))
	lastIndex := int(C.GetStructLastIndex(p.info, C.int(i)))

	structure := make(map[string]interface{}, lastIndex-startIndex)
	for j := startIndex; j < lastIndex; j++ {
		name := p.getPropertyName(j)
		value, err := p.getPropertyValue(j)
		if err != nil {
			return nil, fmt.Errorf("failed parse field %q of complex property type; %w", name, err)
		}
		structure[name] = value
	}
	return structure, nil
}

// For some weird reasons non of mingw versions has TdhFormatProperty defined
// so the only possible way is to use a DLL here.
//
//nolint:gochecknoglobals
var (
	tdh               = windows.NewLazySystemDLL("Tdh.dll")
	tdhFormatProperty = tdh.NewProc("TdhFormatProperty")
)

// parseSimpleType wraps TdhFormatProperty to get rendered to string value of
// @i-th event property.
func (p *propertyParser) parseSimpleType(i int) (string, error) {
	mapInfo, err := getMapInfo(p.record, p.info, i)
	if err != nil {
		return "", fmt.Errorf("failed to get map info; %w", err)
	}

	var propertyLength C.uint
	ret := C.GetPropertyLength(p.record, p.info, C.int(i), &propertyLength)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return "", fmt.Errorf("failed to get property length; %w", status)
	}

	inType := uintptr(C.GetInType(p.info, C.int(i)))
	outType := uintptr(C.GetOutType(p.info, C.int(i)))

	// We are going to guess a value size to save a DLL call, so preallocate.
	var (
		userDataConsumed  C.int
		formattedDataSize C.int = 50
	)
	formattedData := make([]byte, int(formattedDataSize))

retryLoop:
	for {
		r0, _, _ := tdhFormatProperty.Call(
			uintptr(unsafe.Pointer(p.record)),
			uintptr(mapInfo),
			p.ptrSize,
			inType,
			outType,
			uintptr(propertyLength),
			p.endData-p.data,
			p.data,
			uintptr(unsafe.Pointer(&formattedDataSize)),
			uintptr(unsafe.Pointer(&formattedData[0])),
			uintptr(unsafe.Pointer(&userDataConsumed)),
		)

		switch status := windows.Errno(r0); status {
		case windows.ERROR_SUCCESS:
			break retryLoop

		case windows.ERROR_INSUFFICIENT_BUFFER:
			formattedData = make([]byte, int(formattedDataSize))
			continue

		case windows.ERROR_EVT_INVALID_EVENT_DATA:
			// Can happen if the MapInfo doesn't match the actual data, e.g pure ETW provider
			// works with the outdated WEL manifest. Discarding MapInfo allows us to access
			// at least the non-interpreted data.
			if mapInfo != nil {
				mapInfo = nil
				continue
			}
			fallthrough // Can't fix. Error.

		default:
			return "", fmt.Errorf("TdhFormatProperty failed; %w", status)
		}
	}
	p.data += uintptr(userDataConsumed)

	return createUTF16String(uintptr(unsafe.Pointer(&formattedData[0])), int(formattedDataSize)), nil
}

// getMapInfo retrieve the mapping between the @i-th field and the structure it represents.
// If that mapping exists, function extracts it and returns a pointer to the buffer with
// extracted info. If no mapping defined, function can legitimately return `nil, nil`.
func getMapInfo(event C.PEVENT_RECORD, info C.PTRACE_EVENT_INFO, i int) (unsafe.Pointer, error) {
	mapName := C.GetMapName(info, C.int(i))

	// Query map info if any exists.
	var mapSize C.ulong
	ret := C.TdhGetEventMapInformation(event, mapName, nil, &mapSize)
	switch status := windows.Errno(ret); status {
	case windows.ERROR_NOT_FOUND:
		return nil, nil // Pretty ok, just no map info
	case windows.ERROR_INSUFFICIENT_BUFFER:
		// Info exists -- need a buffer.
	default:
		return nil, fmt.Errorf("TdhGetEventMapInformation failed to get size; %w", status)
	}

	// Get the info itself.
	mapInfo := make([]byte, int(mapSize))
	ret = C.TdhGetEventMapInformation(
		event,
		mapName,
		(C.PEVENT_MAP_INFO)(unsafe.Pointer(&mapInfo[0])),
		&mapSize)
	if status := windows.Errno(ret); status != windows.ERROR_SUCCESS {
		return nil, fmt.Errorf("TdhGetEventMapInformation failed; %w", status)
	}

	if len(mapInfo) == 0 {
		return nil, nil
	}
	return unsafe.Pointer(&mapInfo[0]), nil
}

func windowsGUIDToGo(guid C.GUID) windows.GUID {
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
// Actually in go we have no way to make a slice from raw parts, ref:
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
