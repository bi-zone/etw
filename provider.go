package etw

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
// MinGW headers are always restricted to the lowest possible Windows version,
// so specify Win7+ manually.
#undef _WIN32_WINNT
#define _WIN32_WINNT _WIN32_WINNT_WIN7

#include <windows.h>
#include <tdh.h>
 */
import "C"

var (
	enumerateProviders = tdh.NewProc("TdhEnumerateProviders")
)

type Provider struct {
	Name string
	Guid windows.GUID
}

func LookupProvider(name string) (Provider, error) {
	providers, err := ListProviders()
	if err != nil {
		return Provider{}, err
	}
	for _, provider := range providers {
		if provider.Name == name {
			return provider, nil
		}
	}
	return Provider{}, fmt.Errorf("provider not found")
}

func ListProviders() ([]Provider, error) {
	var requiredSize uintptr
	enumerateProviders.Call(0, uintptr(unsafe.Pointer(&requiredSize)))
	status := windows.ERROR_INSUFFICIENT_BUFFER
	var buffer []byte
	for status == windows.ERROR_INSUFFICIENT_BUFFER {
		buffer = make([]byte, requiredSize)
		plainStatus, _, _ := enumerateProviders.Call(
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(unsafe.Pointer(&requiredSize)))
		status = windows.Errno(plainStatus)
	}
	if status != windows.ERROR_SUCCESS {
		return nil, status
	}
	var parsedProviders []Provider
	enumerationInfo := (*C.PROVIDER_ENUMERATION_INFO)(unsafe.Pointer(&buffer[0]))
	// Recast provider info array to escape golang boundary checks
	providerInfoArray := (*[1 << 25]C.TRACE_PROVIDER_INFO)(unsafe.Pointer(&enumerationInfo.TraceProviderInfoArray))
	for _, providerInfo := range providerInfoArray[:enumerationInfo.NumberOfProviders] {
		parsedProviders = append(parsedProviders, Provider{
			Name: parseUnicodeStringAtOffset(buffer, int(providerInfo.ProviderNameOffset)),
			Guid: windowsGUIDToGo(providerInfo.ProviderGuid),
		})
	}
	return parsedProviders, nil
}

func parseUnicodeStringAtOffset(buffer []byte, offset int) string {
	var nameArray []uint16
	for j := offset; j < len(buffer) - 1; j+=2 {
		unicodeChar := binary.LittleEndian.Uint16(buffer[j:])
		if unicodeChar == 0 {
			break
		}
		nameArray = append(nameArray, unicodeChar)
	}
	return string(utf16.Decode(nameArray))
}
