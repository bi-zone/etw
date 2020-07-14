// +build windows

package etw_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	msetw "github.com/Microsoft/go-winio/pkg/etw"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/windows"

	"github.com/bi-zone/etw"
)

func TestSession(t *testing.T) {
	suite.Run(t, new(sessionSuite))
}

type sessionSuite struct {
	suite.Suite

	ctx      context.Context
	cancel   context.CancelFunc
	provider *msetw.Provider
	guid     windows.GUID
}

func (s *sessionSuite) SetupTest() {
	provider, err := msetw.NewProvider("TestProvider", nil)
	s.Require().NoError(err, "Failed to initialize test provider.")

	s.provider = provider
	s.guid = windows.GUID(provider.ID)

	s.ctx, s.cancel = context.WithCancel(context.Background())
}

func (s *sessionSuite) TearDownTest() {
	s.cancel()
	s.Require().NoError(s.provider.Close(), "Failed to close test provider.")
}

// TestSmoke ensures that etw.Session is working as expected: it could start, process incoming
// events and stop properly.
func (s *sessionSuite) TestSmoke() {
	const deadline = 10 * time.Second

	// Spam some events to emulate a normal ETW provider behaviour.
	go s.generateEvents(s.ctx, []msetw.Level{msetw.LevelInfo})

	// Ensure we can subscribe to our in-house ETW provider.
	session, err := etw.NewSession(s.guid)
	s.Require().NoError(err, "Failed to create session")

	// The only thing we are going to do is signal that we've got something.
	gotEvent := make(chan struct{})
	cb := func(_ *etw.Event) {
		s.trySignal(gotEvent)
	}

	// Start the processing routine. We expect the routine will stop on `session.Close()`.
	done := make(chan struct{})
	go func() {
		s.Require().NoError(session.Process(cb), "Error processing events")
		close(done)
	}()

	// Ensure that we are able to receive events from the provider. An ability
	// to get the proper content is tested in TestParsing.
	s.waitForSignal(gotEvent, deadline, "Failed to receive event from provider")

	// Now stop the session and ensure that processing goroutine will also stop.
	s.Require().NoError(session.Close(), "Failed to close session properly")
	s.waitForSignal(done, deadline, "Failed to stop event processing")
}

// TestUpdating ensures that etw.Session is able to update its properties in runtime.
func (s *sessionSuite) TestUpdating() {
	const deadline = 10 * time.Second

	// Create a provider that will spam both INFO and CRITICAL events.
	go s.generateEvents(s.ctx, []msetw.Level{msetw.LevelInfo, msetw.LevelCritical})

	// Then subscribe for CRITICAL only.
	session, err := etw.NewSession(s.guid, etw.WithLevel(etw.TRACE_LEVEL_CRITICAL))
	s.Require().NoError(err, "Failed to create session")

	// Callback will signal about seen event level through corresponding channels.
	var (
		gotCriticalEvent    = make(chan struct{}, 1)
		gotInformationEvent = make(chan struct{}, 1)
	)
	cb := func(e *etw.Event) {
		switch etw.TraceLevel(e.Header.Level) {
		case etw.TRACE_LEVEL_INFORMATION:
			s.trySignal(gotInformationEvent)
		case etw.TRACE_LEVEL_CRITICAL:
			s.trySignal(gotCriticalEvent)
		}
	}
	done := make(chan struct{})
	go func() {
		s.Require().NoError(session.Process(cb), "Error processing events")
		close(done)
	}()

	// Ensure that we are getting INFO events but NO CRITICAL ones.
	s.waitForSignal(gotCriticalEvent, deadline, "Failed to get event with CRITICAL level")
	select {
	case <-time.After(deadline): // pass
	case <-gotInformationEvent:
		s.Fail("Received event with unexpected level")
	}

	// Now bump the subscription option with new event level.
	// (We could actually update any updatable option, level is just the most obvious.)
	err = session.UpdateOptions(etw.WithLevel(etw.TRACE_LEVEL_INFORMATION))
	s.Require().NoError(err, "Failed to update session options")

	// If the options update was successfully applied we should catch event with INFO level too.
	s.waitForSignal(gotInformationEvent, deadline,
		"Failed to receive event with INFO level after updating session options")

	// Stop the session and ensure that processing goroutine will also stop.
	s.Require().NoError(session.Close(), "Failed to close session properly")
	s.waitForSignal(done, deadline, "Failed to stop event processing")
}

// TestParsing ensures that etw.Session is able to parse events with all common field types.
func (s *sessionSuite) TestParsing() {
	const deadline = 20 * time.Second

	go s.generateEvents(
		s.ctx,
		[]msetw.Level{msetw.LevelInfo},
		msetw.StringField("string", "string value"),
		msetw.StringArray("stringArray", []string{"1", "2", "3"}),
		msetw.Float64Field("float64", 45.7),
		msetw.Struct("struct",
			msetw.StringField("string", "string value"),
			msetw.Float64Field("float64", 46.7),
			msetw.Struct("subStructure",
				msetw.StringField("string", "string value"),
			),
		),
		msetw.StringArray("anotherArray", []string{"3", "4"}),
	)
	expectedMap := map[string]interface{}{
		"string":            "string value",
		"stringArray.Count": "3", // OS artifacts
		"stringArray":       []interface{}{"1", "2", "3"},
		"float64":           "45.700000",
		"struct": map[string]interface{}{
			"string": "string value",

			"float64": "46.700000",
			"subStructure": map[string]interface{}{
				"string": "string value",
			},
		},
		"anotherArray.Count": "2", // OS artifacts
		"anotherArray":       []interface{}{"3", "4"},
	}

	session, err := etw.NewSession(s.guid, etw.WithLevel(etw.TRACE_LEVEL_VERBOSE))
	s.Require().NoError(err, "Failed to create a session")

	var (
		properties map[string]interface{}
		gotProps   = make(chan struct{}, 1)
	)
	cb := func(e *etw.Event) {
		properties, err = e.EventProperties()
		s.Require().NoError(err, "Got error parsing event properties")
		s.trySignal(gotProps)
	}

	done := make(chan struct{})
	go func() {
		s.Require().NoError(session.Process(cb), "Error processing events")
		close(done)
	}()

	s.waitForSignal(gotProps, deadline, "Failed to get event")
	s.Equal(expectedMap, properties, "Received unexpected properties")

	s.Require().NoError(session.Close(), "Failed to close session properly")
	s.waitForSignal(done, deadline, "Failed to stop event processing")
}

// TestKillSession ensures that we are able to force kill the lost session using only
// its name.
func (s *sessionSuite) TestKillSession() {
	sessionName := fmt.Sprintf("go-etw-suicide-%d", time.Now().UnixNano())

	// Ensure we can create a session with a given name.
	_, err := etw.NewSession(s.guid, etw.WithName(sessionName))
	s.Require().NoError(err, "Failed to create session with name %s", sessionName)

	// Ensure we've got ExistsError creating a session with the same name.
	_, err = etw.NewSession(s.guid, etw.WithName(sessionName))
	s.Require().Error(err)

	var exists etw.ExistsError
	s.Require().True(errors.As(err, &exists), "Got unexpected error starting session with a same name")
	s.Equal(exists.SessionName, sessionName, "Got unexpected name in etw.ExistsError")

	// Try to force-kill the session by name.
	s.Require().NoError(etw.KillSession(sessionName), "Failed to force stop session")

	// Ensure that fresh session could normally started and stopped.
	session, err := etw.NewSession(s.guid, etw.WithName(sessionName))
	s.Require().NoError(err, "Failed to create session after a successful kill")
	s.Require().NoError(session.Close(), "Failed to close session properly")
}

// TestEventOutsideCallback ensures *etw.Event can't be used outside EventCallback.
func (s *sessionSuite) TestEventOutsideCallback() {
	const deadline = 10 * time.Second
	go s.generateEvents(s.ctx, []msetw.Level{msetw.LevelInfo})

	session, err := etw.NewSession(s.guid)
	s.Require().NoError(err, "Failed to create session")

	// Grab event pointer from the callback. We expect that outdated pointer
	// will protect user from calling Windows API on freed memory.
	var evt *etw.Event
	gotEvent := make(chan struct{})
	cb := func(e *etw.Event) {
		// Signal on second event only to guarantee that callback with stored event will finish.
		if evt != nil {
			s.trySignal(gotEvent)
		} else {
			evt = e
		}
	}
	done := make(chan struct{})
	go func() {
		s.Require().NoError(session.Process(cb), "Error processing events")
		close(done)
	}()

	// Wait for event arrived and try to access event data.
	s.waitForSignal(gotEvent, deadline, "Failed to receive event from provider")
	s.Assert().Zero(evt.ExtendedInfo(), "Got non-nil ExtendedInfo for freed event")
	_, err = evt.EventProperties()
	s.Assert().Error(err, "Don't get an error using freed event")
	s.Assert().Contains(err.Error(), "EventCallback", "Got unexpected error: %s", err)

	s.Require().NoError(session.Close(), "Failed to close session properly")
	s.waitForSignal(done, deadline, "Failed to stop event processing")
}

// trySignal tries to send a signal to @done if it's ready to receive.
// @done expected to be a buffered channel.
func (s sessionSuite) trySignal(done chan<- struct{}) {
	select {
	case done <- struct{}{}:
	default:
	}
}

// waitForSignal waits for anything on @done no longer than @deadline.
// Fails test run if deadline exceeds.
func (s sessionSuite) waitForSignal(done <-chan struct{}, deadline time.Duration, failMsg string) {
	select {
	case <-done:
		// pass.
	case <-time.After(deadline):
		s.Fail(failMsg, "deadline %s exceeded", deadline)
	}
}

// We have no easy way to ensure that etw session is started and ready to process events,
// so it seems easier to just flood an events and catch some of them than try to catch
// the actual session readiness and sent the only one.
func (s sessionSuite) generateEvents(ctx context.Context, levels []msetw.Level, fields ...msetw.FieldOpt) {
	// If nothing provided, receiver doesn't care about the event content -- send anything.
	if fields == nil {
		fields = msetw.WithFields(msetw.StringField("TestField", "Foo"))
	}
	s.Require().NotEmpty(levels, "Incorrect generateEvents usage")

	for {
		select {
		case <-ctx.Done():
			return
		default:
			for _, l := range levels {
				_ = s.provider.WriteEvent(
					"TestEvent",
					msetw.WithEventOpts(msetw.WithLevel(l)),
					fields,
				)
			}
		}
	}
}
