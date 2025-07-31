package retry

import (
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog/log" // TODO: investigate if this is really necessary
)

type permanentError struct {
	err error
}

func (p permanentError) Error() string {
	return p.err.Error()
}

func NewPermanentError(err error) error {
	return permanentError{err: err}
}

func IsPermanentError(err error) bool {
	_, ok := err.(permanentError)
	return ok
}

type Retry struct {
	BackoffInterval   time.Duration
	BackoffMultiplier float64
	BackoffMaxRetries uint64
}

func (r *Retry) RetryHandler(op backoff.Operation) error {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = r.BackoffInterval
	b.Multiplier = r.BackoffMultiplier
	b.RandomizationFactor = 0

	var count int
	wrappedOp := func() error {
		err := op()
		if IsPermanentError(err) {
			fmt.Println("Permanent error detected. Aborting retries.")
			return backoff.Permanent(err) // force backoff to stop
		}
		return err
	}

	notify := func(err error, wait time.Duration) {
		if IsPermanentError(err) {
			fmt.Println("notify: Permanent error – won't retry.")
			return // don't log retry, don't increment count
		}

		count++
		log.Info().
			Err(err).
			Int("attempt", count).
			Dur("wait", wait).
			Msg("retry attempt failed")
	}

	return backoff.RetryNotify(wrappedOp, backoff.WithMaxRetries(b, r.BackoffMaxRetries), notify)
}
