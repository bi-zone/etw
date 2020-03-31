#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7

#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntcons.h>
#include <evntprov.h>
#include <evntrace.h>
#include <securitybaseapi.h>
#include <tdh.h>
#include <in6addr.h>

ULONG CreateSession(TRACEHANDLE* hSession, char* sessionName);
ULONG StartSession(char* sessionName, PVOID context);
ULONGLONG GetPropertyName(PTRACE_EVENT_INFO info, int index);
ULONG GetPropertyCount(PTRACE_EVENT_INFO info, int index);
USHORT GetInType(PTRACE_EVENT_INFO info, int index);
USHORT GetOutType(PTRACE_EVENT_INFO info, int index);