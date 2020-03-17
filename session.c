#include "session.h"

ULONG CreateSession(TRACEHANDLE* hSession, char* sessionName) {
    PEVENT_TRACE_PROPERTIES pSessionProperties = NULL;
    HANDLE hToken = NULL;
    HANDLE hProcess = NULL;

    hProcess = GetCurrentProcess();
    if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken) == FALSE)  {
        printf("Error: Couldn't open the process token\n");
        return 132;
    }

    // if(!SetPrivilege(hToken, SE_SECURITY_NAME, TRUE)) goto cleanup;

    // создание сессии
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