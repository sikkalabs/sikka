package node

import (
	"errors"
	"net/http"
	"testing"

	"besoeasy/sikka/internal/chain"
)

func TestMapAPIError(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{
			name:   "dag closed",
			err:    chain.ErrDAGClosed,
			status: http.StatusServiceUnavailable,
			code:   "dag_closed",
		},
		{
			name:   "insufficient pow",
			err:    errors.New("insufficient PoW: need 4 leading zero bits"),
			status: http.StatusUnprocessableEntity,
			code:   "insufficient_pow",
		},
		{
			name:   "utxo maturity",
			err:    errors.New("input abc:0 not yet mature"),
			status: http.StatusUnprocessableEntity,
			code:   "utxo_not_mature",
		},
		{
			name:   "not found",
			err:    errors.New("parent tx abc not found"),
			status: http.StatusNotFound,
			code:   "not_found",
		},
		{
			name:   "invalid cursor",
			err:    errors.New("unknown after_peer resume key"),
			status: http.StatusBadRequest,
			code:   "invalid_cursor",
		},
		{
			name:   "invalid request",
			err:    errors.New("invalid limit"),
			status: http.StatusBadRequest,
			code:   "invalid_request",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mapped := mapAPIError(tc.err)
			if mapped.Status != tc.status {
				t.Fatalf("status = %d, want %d", mapped.Status, tc.status)
			}
			if mapped.Code != tc.code {
				t.Fatalf("code = %q, want %q", mapped.Code, tc.code)
			}
		})
	}
}
