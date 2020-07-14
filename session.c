#include "session.h"
#include <in6addr.h>

// handleEvent is exported from Go to CGO. Unfortunately CGO can't vary calling
// convention of exported functions (or we don't know da way), so wrap the Go's
// callback with a stdcall one.
extern void handleEvent(PEVENT_RECORD e);

void WINAPI stdcallHandleEvent(PEVENT_RECORD e) {
    handleEvent(e);
}

// OpenTraceHelper helps to access EVENT_TRACE_LOGFILEW union fields and pass
// pointer to C not warning CGO checker.
TRACEHANDLE OpenTraceHelper(LPWSTR name, PVOID ctx) {
    EVENT_TRACE_LOGFILEW trace = {0};
    trace.LoggerName = name;
    trace.Context = ctx;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = stdcallHandleEvent;

    return OpenTraceW(&trace);
}

int getLengthFromProperty(PEVENT_RECORD event, PROPERTY_DATA_DESCRIPTOR* dataDescriptor, UINT32* length) {
    DWORD propertySize = 0;
    ULONG status = ERROR_SUCCESS;
    status = TdhGetPropertySize(event, 0, NULL, 1, dataDescriptor, &propertySize);
    if (status != ERROR_SUCCESS) {
        return status;
    }
    status = TdhGetProperty(event, 0, NULL, 1, dataDescriptor, propertySize, (PBYTE)length);
    return status;
}

// https://docs.microsoft.com/ru-ru/windows/win32/etw/using-tdhformatproperty-to-consume-event-data
ULONG GetArraySize(PEVENT_RECORD event, PTRACE_EVENT_INFO info, int i, UINT32* count) {
    ULONG status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR dataDescriptor;

    if ((info->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount) {
        PROPERTY_DATA_DESCRIPTOR DataDescriptor = {0};
        // Use the countPropertyIndex member of the EVENT_PROPERTY_INFO structure
        // to locate the property that contains the size of the array.
        dataDescriptor.PropertyName = GetPropertyName(info, info->EventPropertyInfoArray[i].countPropertyIndex);
        dataDescriptor.ArrayIndex = ULONG_MAX;
        status = getLengthFromProperty(event, &dataDescriptor, count);
        return status;
    }
    else {
        *count = info->EventPropertyInfoArray[i].count;
        return ERROR_SUCCESS;
    }
}

// GetPropertyLength returns an associated length of the @j-th property of @pInfo.
// If the length is available, retrieve it here. In some cases, the length is 0.
// This can signify that we are dealing with a variable length field such as a structure
// or a string.
ULONG GetPropertyLength(PEVENT_RECORD event, PTRACE_EVENT_INFO info, int i, UINT32* propertyLength) {
    // If the property is a binary blob it can point to another property that defines the
    // blob's size. The PropertyParamLength flag tells you where the blob's size is defined.
    if ((info->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength) {
        ULONG status = ERROR_SUCCESS;
        PROPERTY_DATA_DESCRIPTOR dataDescriptor = {0};
        dataDescriptor.PropertyName = GetPropertyName(info, info->EventPropertyInfoArray[i].lengthPropertyIndex);
        dataDescriptor.ArrayIndex = ULONG_MAX;
        status = getLengthFromProperty(event, &dataDescriptor, propertyLength);
        if (status != ERROR_SUCCESS) {
            return status;
        }
        return ERROR_SUCCESS;
    }

    // If the property is an IP V6 address, you must set the PropertyLength parameter to the size
    // of the IN6_ADDR structure:
    // https://docs.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhformatproperty#remarks
    USHORT inType = info->EventPropertyInfoArray[i].nonStructType.InType;
    USHORT outType = info->EventPropertyInfoArray[i].nonStructType.OutType;
    USHORT TDH_INTYPE_BINARY = 14; // Undefined in MinGW.
    USHORT TDH_OUTTYPE_IPV6 = 24; // Undefined in MinGW.
    if (TDH_INTYPE_BINARY == inType && TDH_OUTTYPE_IPV6 == outType) {
        *propertyLength = sizeof(IN6_ADDR);
        return ERROR_SUCCESS;
    }

    // If no special cases handled -- just return the length defined if the info.
    // In some cases, the length is 0. This can signify that we are dealing with a variable
    // length field such as a structure or a string.
    *propertyLength = info->EventPropertyInfoArray[i].length;
    return ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////////////////////
// All the function below is a helpers for go code to handle dynamic arrays and unnamed unions.
///////////////////////////////////////////////////////////////////////////////////////////////

// Returns ULONGLONG instead of string pointer cos event data descriptor expects exactly that
// type.
ULONGLONG GetPropertyName(PTRACE_EVENT_INFO info , int i) {
    return (ULONGLONG)((PBYTE)(info) + info->EventPropertyInfoArray[i].NameOffset);
}

USHORT GetInType(PTRACE_EVENT_INFO info, int i) {
    return info->EventPropertyInfoArray[i].nonStructType.InType;
}

USHORT GetOutType(PTRACE_EVENT_INFO info, int i) {
    return info->EventPropertyInfoArray[i].nonStructType.OutType;
}

LPWSTR GetMapName(PTRACE_EVENT_INFO info, int i) {
    return (LPWSTR)((PBYTE)(info) + info->EventPropertyInfoArray[i].nonStructType.MapNameOffset);
}

BOOL PropertyIsStruct(PTRACE_EVENT_INFO info, int i) {
    return (info->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct;
}

// Determine whether the property is an array. The property is an array
// if the EVENT_PROPERTY_INFO.Flags member is set to PropertyParamCount
// or the EVENT_PROPERTY_INFO.count member is greater than 1.
//
// https://docs.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhformatproperty#remarks
BOOL PropertyIsArray(PTRACE_EVENT_INFO info, int i) {
    return
    ((info->EventPropertyInfoArray[i].Flags & PropertyParamCount) == PropertyParamCount) ||
    (info->EventPropertyInfoArray[i].count > 1);
}

int GetStructStartIndex(PTRACE_EVENT_INFO info, int i) {
    return info->EventPropertyInfoArray[i].structType.StructStartIndex;
}

int GetStructLastIndex(PTRACE_EVENT_INFO info, int i) {
    return info->EventPropertyInfoArray[i].structType.StructStartIndex +
                    info->EventPropertyInfoArray[i].structType.NumOfStructMembers;
}

LONGLONG GetTimeStamp(EVENT_HEADER header) {
    return header.TimeStamp.QuadPart;
}

ULONG GetKernelTime(EVENT_HEADER header) {
    return header.KernelTime;
}

ULONG GetUserTime(EVENT_HEADER header) {
    return header.UserTime;
}

ULONG64 GetProcessorTime(EVENT_HEADER header) {
    return header.ProcessorTime;
}

USHORT GetExtType(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int i) {
    return extData[i].ExtType;
}

ULONGLONG GetDataPtr(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int i) {
    return extData[i].DataPtr;
}

USHORT GetDataSize(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int i) {
     return extData[i].DataSize;
}

ULONG GetAddress32(PEVENT_EXTENDED_ITEM_STACK_TRACE32 trace32, int j) {
    return trace32->Address[j];
}

ULONGLONG GetAddress64(PEVENT_EXTENDED_ITEM_STACK_TRACE64 trace64, int j) {
   return trace64->Address[j];
}
