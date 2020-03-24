#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntcons.h>
#include <evntprov.h>
#include <evntrace.h>
#include <securitybaseapi.h>
#include <tdh.h>
#pragma comment(lib, "tdh.lib")

ULONG CreateSession(TRACEHANDLE* hSession, char* sessionName);
ULONG StartSession(char* sessionName, PVOID context);
//TRACE_EVENT_INFO GetEventInformation(EVENT_RECORD* pEvent);
