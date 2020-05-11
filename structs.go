package tracing_session

/*
#include "session.h"
*/
import "C"

// TODO: options, types

// TODO: GO-style names for flags with appropriate description?
type SessionOptions struct {
	Name             string
	Level            TraceLevel
	MatchAnyKeyword  uint64
	MatchAllKeyword  uint64
	EnableProperties []EnableProperty
}

func WithName(name string) Option {
	return func(cfg *SessionOptions) {
		cfg.Name = name
	}
}

func WithLevel(lvl TraceLevel) Option {
	return func(cfg *SessionOptions) {
		cfg.Level = lvl
	}
}

func WithMatchKeywords(anyKeyword, allKeyword uint64) Option {
	return func(cfg *SessionOptions) {
		cfg.MatchAnyKeyword = anyKeyword
		cfg.MatchAllKeyword = allKeyword
	}
}

func WithProperty(p EnableProperty) Option {
	return func(cfg *SessionOptions) {
		cfg.EnableProperties = append(cfg.EnableProperties, p)
	}
}

type TraceLevel C.UCHAR

const (
	TRACE_LEVEL_CRITICAL    = TraceLevel(1)
	TRACE_LEVEL_ERROR       = TraceLevel(2)
	TRACE_LEVEL_WARNING     = TraceLevel(3)
	TRACE_LEVEL_INFORMATION = TraceLevel(4)
	TRACE_LEVEL_VERBOSE     = TraceLevel(5)
)

type EnableProperty C.ULONG

const (
	EVENT_ENABLE_PROPERTY_SID               = EnableProperty(0x001)
	EVENT_ENABLE_PROPERTY_TS_ID             = EnableProperty(0x002)
	EVENT_ENABLE_PROPERTY_STACK_TRACE       = EnableProperty(0x004)
	EVENT_ENABLE_PROPERTY_PSM_KEY           = EnableProperty(0x008)
	EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0  = EnableProperty(0x010)
	EVENT_ENABLE_PROPERTY_PROVIDER_GROUP    = EnableProperty(0x020)
	EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0  = EnableProperty(0x040)
	EVENT_ENABLE_PROPERTY_PROCESS_START_KEY = EnableProperty(0x080)
	EVENT_ENABLE_PROPERTY_EVENT_KEY         = EnableProperty(0x100)
	EVENT_ENABLE_PROPERTY_EXCLUDE_INPRIVATE = EnableProperty(0x200)
)
