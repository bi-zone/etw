#include "session.h"
#include "_cgo_export.h"

ULONG CreateSession(TRACEHANDLE* hSession, PEVENT_TRACE_PROPERTIES* properties, char* sessionName) {
    *properties = NULL;

    const size_t buffSize = sizeof(EVENT_TRACE_PROPERTIES) + strlen(sessionName) + 1;
    *properties = calloc(buffSize, sizeof(char));
    (*properties)->Wnode.BufferSize = buffSize;
    (*properties)->Wnode.ClientContext = 1;
    (*properties)->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    (*properties)->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    (*properties)->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    return StartTrace(hSession, sessionName, *properties);
};

ULONG StartSession(char* sessionName, PVOID context) {
    ULONG status = ERROR_SUCCESS;
    EVENT_TRACE_LOGFILE trace;
    TRACEHANDLE hTrace = 0;

    ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
    trace.LogFileName = NULL;
    trace.LoggerName = sessionName;
    trace.CurrentTime = 0;
    trace.BuffersRead = 0;
    trace.BufferSize = 0;
    trace.Filled = 0;
    trace.EventsLost = 0;
    trace.Context = context;
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(handleEvent);

    hTrace = OpenTrace(&trace);

    if (INVALID_PROCESSTRACE_HANDLE == hTrace) {
        return GetLastError();
    }

    status = ProcessTrace(&hTrace, 1, 0, 0);
    if (status != ERROR_SUCCESS && status != ERROR_CANCELLED) {
        return status;
    }
}

ULONGLONG GetPropertyName(PTRACE_EVENT_INFO info , int i) {
    return (ULONGLONG)((PBYTE)(info) + info->EventPropertyInfoArray[i].NameOffset);
}

ULONG GetPropertyCount(PTRACE_EVENT_INFO info, int i) {
    return info->EventPropertyInfoArray[i].count;
}

USHORT GetInType(PTRACE_EVENT_INFO info, int i) {
    return info->EventPropertyInfoArray[i].nonStructType.InType;
}

USHORT GetOutType(PTRACE_EVENT_INFO info, int i) {
    return info->EventPropertyInfoArray[i].nonStructType.OutType;
}

void RemoveTrailingSpace(PEVENT_MAP_INFO pMapInfo) {
    DWORD ByteLength = 0;

    for (DWORD i = 0; i < pMapInfo->EntryCount; i++) {
        ByteLength = (wcslen((LPWSTR)((PBYTE)pMapInfo + pMapInfo->MapEntryArray[i].OutputOffset)) - 1) * 2;
        *((LPWSTR)((PBYTE)pMapInfo + (pMapInfo->MapEntryArray[i].OutputOffset + ByteLength))) = L'\0';
    }
}

DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, int i, int* PropertyLength) {
    DWORD status = ERROR_SUCCESS;
    PROPERTY_DATA_DESCRIPTOR DataDescriptor;
    DWORD PropertySize = 0;

    // If the property is a binary blob and is defined in a manifest, the property can
    // specify the blob's size or it can point to another property that defines the
    // blob's size. The PropertyParamLength flag tells you where the blob's size is defined.

    if ((pInfo->EventPropertyInfoArray[i].Flags & PropertyParamLength) == PropertyParamLength) {
        DWORD Length = 0;  // Expects the length to be defined by a UINT16 or UINT32
        DWORD j = pInfo->EventPropertyInfoArray[i].lengthPropertyIndex;
        ZeroMemory(&DataDescriptor, sizeof(PROPERTY_DATA_DESCRIPTOR));
        DataDescriptor.PropertyName = (ULONGLONG)((PBYTE)(pInfo) + pInfo->EventPropertyInfoArray[j].NameOffset);
        DataDescriptor.ArrayIndex = ULONG_MAX;
        status = TdhGetPropertySize(pEvent, 0, NULL, 1, &DataDescriptor, &PropertySize);
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
                wprintf(L"Unexpected length of 0 for intype %d and outtype %d\n",
                    pInfo->EventPropertyInfoArray[i].nonStructType.InType,
                    pInfo->EventPropertyInfoArray[i].nonStructType.OutType);

                status = ERROR_EVT_INVALID_EVENT_DATA;
                goto cleanup;
            }
        }
    }

cleanup:

    return status;
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

ULONGLONG GetTimeStamp(PEVENT_RECORD EventRecord) {
    ULONGLONG time;
    time = EventRecord->EventHeader.TimeStamp.HighPart;
    time = (time << 32) | EventRecord->EventHeader.TimeStamp.LowPart;
    return time;
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



typedef struct _EVENT_FILTER_EVENT_ID {
  BOOLEAN FilterIn;
  UCHAR   Reserved;
  USHORT  Count;
  USHORT  Events[ANYSIZE_ARRAY];
} EVENT_FILTER_EVENT_ID, *PEVENT_FILTER_EVENT_ID;

ULONGLONG CreateEventDescriptor(EVENT_FILTER_DESCRIPTOR* filterDesc) {
    int memorySize = sizeof(EVENT_FILTER_EVENT_ID) + sizeof(USHORT) * 1;
    char* memory = malloc(memorySize);

    EVENT_FILTER_EVENT_ID* filterEventIds = (EVENT_FILTER_EVENT_ID*)memory;

    filterEventIds->FilterIn = TRUE;
    filterEventIds->Reserved = 0;
    filterEventIds->Count = 1;

    filterEventIds->Events[0] = 11;

    filterDesc->Ptr = (ULONGLONG)filterEventIds;
    filterDesc->Size = (ULONG)(memorySize);
    filterDesc->Type = 0x80000200;

    return 0;
}