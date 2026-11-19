package client

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	coreErrs "github.com/apernet/hysteria/core/v2/errors"

	"github.com/apernet/quic-go"
)

func TestWrapIfConnectionClosed(t *testing.T) {
	// quic-go returns *StreamLimitReachedError from OpenStream
	for _, err := range []error{
		&quic.StreamLimitReachedError{},
		quic.StreamLimitReachedError{},
		fmt.Errorf("open stream: %w", &quic.StreamLimitReachedError{}),
	} {
		assert.Equal(t, err, wrapIfConnectionClosed(err))
	}

	err := errors.New("connection lost")
	assert.Equal(t, coreErrs.ClosedError{Err: err}, wrapIfConnectionClosed(err))
}
