// +build windows

package etw

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Microsoft/go-winio/pkg/etw"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/windows"
)

type testProvider struct {
	suite.Suite

	provider *etw.Provider
	guid     windows.GUID
}

func (p *testProvider) SetupSuite() {
	provider, err := etw.NewProvider("TestProvider", nil)
	p.Require().NoError(err, "Failed to initialize test provider.")
	p.provider = provider
	p.guid = (windows.GUID)(provider.ID)
}

func (p *testProvider) TearDownSuite() {
	p.Require().NoError(p.provider.Close(), "Failed to close test provider.")
}

func (p testProvider) generateEvents(ctx context.Context, levels []etw.Level, fields ...etw.FieldOpt) {
	if fields == nil {
		fields = etw.WithFields(etw.StringField("TestField", "Foo"))
	}
	for {
		select {
		case <-ctx.Done():
			return
		default:
			for _, l := range levels {
				_ = p.provider.WriteEvent("TestEvent", etw.WithEventOpts(etw.WithLevel(l)), fields)
			}
		}
	}
}

func (p *testProvider) TestSession_StartStop() {
	ctx, cancel := context.WithCancel(context.Background())
	go p.generateEvents(ctx, []etw.Level{etw.LevelInfo})
	defer func() {
		cancel()
	}()

	session, err := NewSession(p.guid)
	if err != nil {
		p.Fail("Failed to create session", "%s", err)
	}

	gotEvent := make(chan struct{})
	var once sync.Once
	cb := func(e *Event) {
		once.Do(func() { close(gotEvent) })
	}

	done := make(chan struct{})
	go func() {
		err := session.Process(cb)
		if err != nil {
			p.Fail("Failed to start processing events", "%s", err)
		}
		close(done)
	}()

	deadline := 10 * time.Second

	// Wait for the first event from the provider.
	select {
	case <-gotEvent:
		// Pass.
	case <-time.After(deadline):
		p.Fail("Failed to receive event from provider", "deadline %s exceeded", deadline.String())
	}

	if err := session.Close(); err != nil {
		p.Fail("Failed to close session properly", "%s", err)
	}

	// Ensure processing goroutine wont block forever.
	select {
	case <-done:
		// Pass.
	case <-time.After(deadline):
		p.Fail("Failed to stop event processing", "deadline %s exceeded", deadline.String())
	}
}

func (p *testProvider) TestUpdating() {
	ctx, cancel := context.WithCancel(context.Background())
	go p.generateEvents(ctx, []etw.Level{etw.LevelInfo, etw.LevelCritical})
	defer func() {
		cancel()
	}()

	session, err := NewSession(p.guid, WithLevel(TRACE_LEVEL_CRITICAL))
	if err != nil {
		p.Require().NoError(err, "Failed to create session")
	}

	// callback signals about event level through corresponding channels.
	gotCriticalEvent := make(chan struct{}, 1)
	gotInformationEvent := make(chan struct{}, 1)
	cb := func(e *Event) {
		switch TraceLevel(e.Header.Level) {
		case TRACE_LEVEL_INFORMATION:
			select {
			case gotInformationEvent <- struct{}{}:
			default:
			}
		case TRACE_LEVEL_CRITICAL:
			select {
			case gotCriticalEvent <- struct{}{}:
			default:
			}
		default:
		}
	}

	done := make(chan struct{})
	go func() {
		err := session.Process(cb)
		p.Require().NoError(err, "Failed to start processing events")
		close(done)
	}()

	deadline := 10 * time.Second

	// Ensure that we are receiving events with Critical level only.
	select {
	case <-gotCriticalEvent:
		// pass
	case <-time.After(deadline):
		p.Fail(
			"Failed to get event with critical level",
			"deadline %s exceeded", deadline.String())
	}
	select {
	case <-gotInformationEvent:
		p.Fail("Received event with unexpected level")
	case <-time.After(deadline):
		// pass
	}

	if err := session.UpdateOptions(WithLevel(TRACE_LEVEL_INFORMATION)); err != nil {
		p.Failf("Failed to update session options", "%s", err)
	}

	// Ensure option updates are applied:
	// after options updating, we should receive events with both levels.
	select {
	case <-gotInformationEvent:
		// pass
	case <-time.After(deadline):
		p.Fail(
			"Failed to receive event with INFO level after updating session options",
			"deadline %s exceeded", deadline.String())
	}

	// Stop the session properly.
	if err := session.Close(); err != nil {
		p.Fail("Failed to close session properly", "%s", err)
	}
	// Ensure processing goroutine wont block forever.
	select {
	case <-done:
		// Pass.
	case <-time.After(deadline):
		p.Fail("Failed to stop event processing", "deadline %s exceeded", deadline.String())
	}
}

func (p *testProvider) TestParsing() {
	ctx, cancel := context.WithCancel(context.Background())
	go p.generateEvents(
		ctx,
		[]etw.Level{etw.LevelInfo},
		etw.StringField("string", "string value"),
		etw.StringArray("stringArray", []string{"1", "2", "3"}),
		etw.Float64Field("float64", 45.7),
		etw.Struct("struct",
			etw.StringField("string", "string value"),
			etw.Float64Field("float64", 46.7),
			etw.Struct("subStructure",
				etw.StringField("string", "string value"))),
		etw.StringArray("anotherArray", []string{"3", "4"}),
	)

	expectedMap := map[string]interface{}{
		"string":            "string value",
		"stringArray.Count": "3", // os's artifacts
		"stringArray":       []interface{}{"1", "2", "3"},
		"float64":           "45.700000",
		"struct": map[string]interface{}{
			"string": "string value",

			"float64": "46.700000",
			"subStructure": map[string]interface{}{
				"string": "string value",
			},
		},
		"anotherArray.Count": "2", // os's artifacts
		"anotherArray":       []interface{}{"3", "4"},
	}

	defer func() {
		cancel()
	}()

	session, err := NewSession(p.guid, WithLevel(TRACE_LEVEL_VERBOSE))
	if err != nil {
		p.Require().NoError(err, "Failed to create session")
	}

	propCh := make(chan map[string]interface{}, 1)
	cb := func(e *Event) {
		properties, _ := e.EventProperties()
		select {
		case propCh <- properties:
		default:
		}
	}

	done := make(chan struct{})
	go func() {
		err := session.Process(cb)
		p.Require().NoError(err, "Failed to start processing events")
		close(done)
	}()

	deadline := 10 * time.Second
	select {
	case properties := <-propCh:
		p.Equal(expectedMap, properties, "Received unexpected properties")
	case <-time.After(deadline):
		p.Fail("Failed to get event properties", "deadline %s exceeded", deadline.String())
	}

	// Stop the session properly.
	if err := session.Close(); err != nil {
		p.Fail("Failed to close session properly", "%s", err)
	}
	// Ensure processing goroutine wont block forever.
	select {
	case <-done:
		// Pass.
	case <-time.After(deadline):
		p.Fail("Failed to stop event processing", "deadline %s exceeded", deadline.String())
	}

}

func (p *testProvider) TestKillSession() {
	const sessionName = "Suicide session"

	// Creating the session.
	session, err := NewSession(p.guid, WithName(sessionName))
	if err != nil {
		p.Fail("Failed to create session", "%s", err)
	}

	// Ensure attempt of creating a session with the
	// same name fails with ExistError.
	_, err = NewSession(p.guid, WithName(sessionName))
	var exists ExistError
	if !errors.As(err, &exists) {
		p.Fail(
			"The attempt of creating a session with the same name failed with not expected err",
			"%s", err)
	}

	// Killing the session by name.
	if err := KillSession(sessionName); err != nil {
		p.Fail("Failed to force stop session", "%s", err)
	}

	// Trying to create new session with the same name.
	// Then stop the session properly.
	session, err = NewSession(p.guid, WithName(sessionName))
	if err != nil {
		p.Fail("Failed to create session", "%s", err)
	}

	if err := session.Close(); err != nil {
		p.Fail("Failed to close session properly", "%s", err)
	}
}

func TestSession(t *testing.T) {
	suite.Run(t, new(testProvider))
}
