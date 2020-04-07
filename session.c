#include "session.h"
#include "_cgo_export.h"

ULONG CreateSession(TRACEHANDLE* hSession, char* sessionName) {
    PEVENT_TRACE_PROPERTIES pSessionProperties = NULL;
    HANDLE hToken = NULL;
    HANDLE hProcess = NULL;

    hProcess = GetCurrentProcess();
    if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken) == FALSE)  {
        printf("Error: Couldn't open the process token\n");
        return 132;
    }

    const size_t buffSize = sizeof(EVENT_TRACE_PROPERTIES) + strlen(sessionName) + 1;
    pSessionProperties = malloc(buffSize);
    ZeroMemory(pSessionProperties, buffSize);
    pSessionProperties->Wnode.BufferSize = buffSize;
    pSessionProperties->Wnode.ClientContext = 1;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    return StartTrace(hSession, sessionName, pSessionProperties);
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

