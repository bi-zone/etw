#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7

#include <windows.h>
#include <stdio.h>
#include <evntcons.h>
#include <evntprov.h>
#include <evntrace.h>
#include <tdh.h>
#include <in6addr.h>

ULONG CreateSession(TRACEHANDLE* hSession, PEVENT_TRACE_PROPERTIES* properties, char* sessionName);
ULONG StartSession(char* sessionName, PVOID context);

// Helpers for event property parsing.
ULONGLONG GetPropertyName(PTRACE_EVENT_INFO info, int index);
USHORT GetInType(PTRACE_EVENT_INFO info, int index);
USHORT GetOutType(PTRACE_EVENT_INFO info, int index);
LPWSTR GetMapName(PTRACE_EVENT_INFO info, int i);
DWORD GetPropertyLength(PEVENT_RECORD pEvent, PTRACE_EVENT_INFO pInfo, int i, int* PropertyLength);
int PropertyIsStruct(PTRACE_EVENT_INFO info, int i);
int GetStartIndex(PTRACE_EVENT_INFO info, int i);
int GetLastIndex(PTRACE_EVENT_INFO info, int i);
ULONGLONG GetTimeStamp(PEVENT_RECORD EventRecord);
ULONG GetKernelTime(EVENT_HEADER header);
ULONG GetUserTime(EVENT_HEADER header);

// Helpers for extended data parsing.
USHORT GetExtType(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int i);
ULONGLONG GetDataPtr(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int i);
USHORT GetDataSize(PEVENT_HEADER_EXTENDED_DATA_ITEM extData, int i);
ULONG GetAddress32(PEVENT_EXTENDED_ITEM_STACK_TRACE32 trace32, int j);
ULONGLONG GetAddress64(PEVENT_EXTENDED_ITEM_STACK_TRACE64 trace64, int j);
