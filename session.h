#include <windows.h>
#include <stdio.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <Evntrace.h>
#include <evntcons.h>

ULONG CreateSession(TRACEHANDLE* hSession, char* sessionName);
