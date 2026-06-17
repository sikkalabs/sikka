package chain

import "errors"

// ErrDAGClosed is returned when a mutating DAG operation is attempted after Close.
var ErrDAGClosed = errors.New("dag is closed")
