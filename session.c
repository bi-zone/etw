#include "session.h"

// TODO: why not to do it in go?
ULONG CreateSession(TRACEHANDLE* hSession, PEVENT_TRACE_PROPERTIES* properties, char* sessionName) {
    const size_t buffSize = sizeof(EVENT_TRACE_PROPERTIES) + strlen(sessionName) + 1;
    *properties = calloc(buffSize, sizeof(char));
    (*properties)->Wnode.BufferSize = buffSize;
    (*properties)->Wnode.ClientContext = 1;
    (*properties)->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    (*properties)->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    (*properties)->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    // TODO: is it StartTraceW or StartTraceA?
    return StartTrace(hSession, sessionName, *properties);
};

ULONG StartSession(char* sessionName, PVOID context, PEVENT_RECORD_CALLBACK cb) {
    EVENT_TRACE_LOGFILE trace = {0};
    trace.LoggerName = sessionName;
    trace.Context = context;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = cb;

    TRACEHANDLE hTrace = OpenTrace(&trace);
    if (INVALID_PROCESSTRACE_HANDLE == hTrace) {
        return GetLastError();
    }

    // TODO: named constants.
    return ProcessTrace(&hTrace, 1, 0, 0);
}

DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, int i, int* PropertyLength) {
    DWORD status = ERROR_SUCCESS;

    // If the property is a binary blob and is defined in a manifest, the property can
    // specify the blob's size or it can point to another property that defines the
    // blob's size. The PropertyParamLength flag tells you where the blob's size is defined.

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength) {
        DWORD j = pInfo->EventPropertyInfoArray[i].lengthPropertyIndex;

        PROPERTY_DATA_DESCRIPTOR DataDescriptor = {0};
        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;

        // TODO: handle statuses properly.
        DWORD PropertySize = 0;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);

        DWORD Length = 0;  // Expects the length to be defined by a UINT16 or UINT32 // TODO: just pass PropertyLength itself?
        status = TdhGetProperty(pEvent, 0, NULL, 1, &DataDescriptor, PropertySize, (PBYTE)&Length);
        *PropertyLength = (int)Length;
    }
    else {
        if (pInfo->EventPropertyInfoArray[i].length > 0) {
            *PropertyLength = pInfo->EventPropertyInfoArray[i].length;
        }
        else {
            // If the property is a binary blob and is defined in a MOF class, the extension
            // qualifier is used to determine the size of the blob. However, if the extension
            // is IPAddrV6, you must set the PropertyLength variable yourself because the
            // EVENT_PROPERTY_INFO.length field will be zero.

            // TODO: named constants
            if (14 == pInfo->EventPropertyInfoArray[i].nonStructType.InType &&
                24 == pInfo->EventPropertyInfoArray[i].nonStructType.OutType) {
                *PropertyLength = (int)sizeof(IN6_ADDR);
            }
            else if (1 == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
                     2 == pInfo->EventPropertyInfoArray[i].nonStructType.InType ||
                     (pInfo->EventPropertyInfoArray[i].Flags & PropertyStruct) == PropertyStruct) {
                *PropertyLength = pInfo->EventPropertyInfoArray[i].length;
            }
            else {
                // TODO: handle error properly.
                wprintf(L"Unexpected length of 0 for intype %d and outtype %d\n",
                    pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[i].nonStructType.OutType);

                status = ERROR_EVT_INVALID_EVENT_DATA;
                goto cleanup;
            }
        }
    }

// TODO: is it ok that there is no cleanup? Change to naked return if so?
cleanup:

    return status;
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
