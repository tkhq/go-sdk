package turnkey

import (
	"errors"
	"fmt"
)

// RequestType distinguishes activity requests (which poll to completion) from query requests.
type RequestType string

const (
	RequestTypeQuery    RequestType = "query"
	RequestTypeActivity RequestType = "activity"
)

// SignedRequest contains a JSON body and stamp for callers that submit requests themselves.
type SignedRequest struct {
	URL   string      `json:"url"`
	Body  string      `json:"body"`
	Stamp *Stamp      `json:"stamp,omitempty"`
	Type  RequestType `json:"type,omitempty"`
}

// RequestError is returned for non-2xx Turnkey API responses.
type RequestError struct {
	StatusCode int
	Status     *RPCStatus
	Body       []byte
}

func (e *RequestError) Error() string {
	if e.Status != nil && e.Status.Message != nil && *e.Status.Message != "" {
		return fmt.Sprintf("turnkey: %s (status=%d)", *e.Status.Message, e.StatusCode)
	}

	return fmt.Sprintf("turnkey: request failed (status=%d)", e.StatusCode)
}

type errorResponse struct {
	Code    *int          `json:"code,omitempty"`
	Message *string       `json:"message,omitempty"`
	Details []ProtobufAny `json:"details,omitempty"`
}

// ActivityResult is a typed activity response with the operation-specific result lifted out.
type ActivityResult[T any] struct {
	Activity Activity `json:"activity"`
	Result   *T       `json:"result,omitempty"`
}

// ActivityFailedError is returned when an activity reaches a failed or rejected terminal state.
type ActivityFailedError struct {
	ActivityID string
	Status     ActivityStatus
	Failure    *RPCStatus
}

// Error formats the activity failure for display. If the RPCStatus contains a message, it is included in the error string.
func (e *ActivityFailedError) Error() string {
	if e.Failure != nil && e.Failure.Message != nil {
		return fmt.Sprintf("activity %s %s: %s", e.ActivityID, e.Status, *e.Failure.Message)
	}

	return fmt.Sprintf("activity %s: %s", e.ActivityID, e.Status)
}

// ActivityRequiresApprovalError is returned when an activity requires consensus approval.
// The full Activity is attached so the caller can drive their own polling/lifecycle.
type ActivityRequiresApprovalError struct {
	ActivityID string
	Activity   Activity
}

func (e *ActivityRequiresApprovalError) Error() string {
	return fmt.Sprintf("activity %s requires approval", e.ActivityID)
}

// ActivityFromApprovalError returns the activity attached to an approval-required error.
func ActivityFromApprovalError(err error) (Activity, bool) {
	var approvalErr *ActivityRequiresApprovalError
	if errors.As(err, &approvalErr) {
		return approvalErr.Activity, true
	}

	return Activity{}, false
}
