#include "session.h"

// OpenTraceHelper helps to access EVENT_TRACE_LOGFILEW union fields and pass
// pointer to C not warning CGO checker.
TRACEHANDLE OpenTraceHelper(LPWSTR name, PVOID ctx, PEVENT_RECORD_CALLBACK cb) {
    EVENT_TRACE_LOGFILEW trace = {0};
    trace.LoggerName = name;
    trace.Context = ctx;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = cb;

    return OpenTraceW(&trace);
}

// GetPropertyLength returns an associated length of the @j-th property of @pInfo.
// If the length is available, retrieve it here. In some cases, the length is 0.
// This can signify that we are dealing with a variable length field such as a structure
// or a string.
DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, int i, UINT32* PropertyLength) {
    // If the property is a binary blob it can point to another property that defines the
    // blob's size. The PropertyParamLength flag tells you where the blob's size is defined.
    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength) {
        PROPERTY_DATA_DESCRIPTOR DataDescriptor = {0};
        DataDescriptor.PropertyName = GetPropertyName(pInfo, pInfo->EventPropertyInfoArray[i].lengthPropertyIndex);
        DataDescriptor.ArrayIndex = ULONG_MAX;

        DWORD PropertySize = 0;
        ULONG status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
        if (status != ERROR_SUCCESS) {
            return status;
        }

        DWORD Length = 0;
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Length);
        if (status != ERROR_SUCCESS) {
            return status;
        }
        *PropertyLength = Length;
        return ERROR_SUCCESS;
    }

    // If the property is an IP V6 address, you must set the PropertyLength parameter to the size
    // of the IN6_ADDR structure:
    // https://docs.microsoft.com/en-us/windows/win32/api/tdh/nf-tdh-tdhformatproperty#remarks
    USHORT inType = pInfo->EventPropertyInfoArray[i].nonStructType.InType;
    USHORT outType = pInfo->EventPropertyInfoArray[i].nonStructType.OutType;
    USHORT TDH_INTYPE_BINARY = 14; // Undefined in MinGW.
    USHORT TDH_OUTTYPE_IPV6 = 24; // Undefined in MinGW.
    if (TDH_INTYPE_BINARY == inType && TDH_OUTTYPE_IPV6 == outType) {
        *PropertyLength = sizeof(IN6_ADDR);
        return ERROR_SUCCESS;
    }

    // If no special cases handled -- just return the length defined if the info.
    // In some cases, the length is 0. This can signify that we are dealing with a variable
    // length field such as a structure or a string.
    *PropertyLength = pInfo->EventPropertyInfoArray[i].length;
    return ERROR_SUCCESS;
}

///////////////////////////////////////////////////////////////////////////////////////////////
// All the function below is a helpers for go code to handle dynamic arrays and unnamed unions.
///////////////////////////////////////////////////////////////////////////////////////////////


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

int PropertyIsStruct(PTRACE_EVENT_INFO info, int i) {
    return (info->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct;
}

int GetStartIndex(PTRACE_EVENT_INFO info, int i) {
    return info->EventPropertyInfoArray[i].structType.StructStartIndex;
}

int GetLastIndex(PTRACE_EVENT_INFO info, int i) {
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
