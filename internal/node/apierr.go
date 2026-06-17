package node

import (
	"errors"
	"net/http"
	"strings"

	"besoeasy/sikka/internal/chain"
)

type apiErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type mappedAPIError struct {
	Status  int
	Code    string
	Message string
}

func mapAPIError(err error) mappedAPIError {
	if err == nil {
		return mappedAPIError{
			Status:  http.StatusInternalServerError,
			Code:    "internal_error",
			Message: "internal error",
		}
	}

	msg := err.Error()
	lower := strings.ToLower(msg)

	if errors.Is(err, chain.ErrDAGClosed) {
		return mappedAPIError{http.StatusServiceUnavailable, "dag_closed", msg}
	}

	switch {
	case strings.Contains(lower, "insufficient pow"):
		return mappedAPIError{http.StatusUnprocessableEntity, "insufficient_pow", msg}
	case strings.Contains(lower, "not yet mature"),
		strings.Contains(lower, "missing created_at"):
		return mappedAPIError{http.StatusUnprocessableEntity, "utxo_not_mature", msg}
	case strings.Contains(lower, "witness"),
		strings.Contains(lower, "signature"),
		strings.Contains(lower, "unsupported"):
		return mappedAPIError{http.StatusUnprocessableEntity, "invalid_witness", msg}
	case strings.Contains(lower, "parent_pow_hashes"),
		strings.Contains(lower, "stale"),
		strings.Contains(lower, "changed between snapshot"):
		return mappedAPIError{http.StatusConflict, "conflict", msg}
	case strings.Contains(lower, "not found"):
		return mappedAPIError{http.StatusNotFound, "not_found", msg}
	case strings.Contains(lower, "unknown after"),
		strings.Contains(lower, "unknown after_outpoint"),
		strings.Contains(lower, "unknown after_peer"):
		return mappedAPIError{http.StatusBadRequest, "invalid_cursor", msg}
	case strings.Contains(lower, "too many"),
		strings.Contains(lower, "too long"),
		strings.Contains(lower, "have list"):
		return mappedAPIError{http.StatusBadRequest, "invalid_request", msg}
	case strings.Contains(lower, "invalid body"),
		strings.Contains(lower, "invalid request body"),
		strings.Contains(lower, "invalid limit"),
		strings.Contains(lower, "invalid after"),
		strings.Contains(lower, "invalid non-negative"),
		strings.Contains(lower, "addresses are required"),
		strings.Contains(lower, "missing address"),
		strings.Contains(lower, "requires both"):
		return mappedAPIError{http.StatusBadRequest, "invalid_request", msg}
	default:
		return mappedAPIError{http.StatusBadRequest, "invalid_request", msg}
	}
}

func (n *Node) writeRequestError(w http.ResponseWriter, err error) {
	mapped := mapAPIError(err)
	if mapped.Status >= http.StatusInternalServerError {
		n.log.Error("api error", "code", mapped.Code, "err", err)
	} else if mapped.Status >= http.StatusBadRequest {
		n.log.Debug("api request rejected", "code", mapped.Code, "err", err)
	}
	n.writeJSON(w, mapped.Status, apiErrorBody{
		Code:    mapped.Code,
		Message: mapped.Message,
	})
}

func (n *Node) writeErrorResponse(w http.ResponseWriter, status int, code, message string) {
	if status >= http.StatusInternalServerError {
		n.log.Error("api error", "code", code, "message", message)
	} else if status >= http.StatusBadRequest {
		n.log.Debug("api request rejected", "code", code, "message", message)
	}
	n.writeJSON(w, status, apiErrorBody{Code: code, Message: message})
}
