// Code generated by go-swagger; DO NOT EDIT.

package user_auth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new user auth API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for user auth API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	EmailAuth(params *EmailAuthParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*EmailAuthOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
EmailAuth performs email auth

Authenticate a user via Email
*/
func (a *Client) EmailAuth(params *EmailAuthParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*EmailAuthOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewEmailAuthParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "EmailAuth",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/email_auth",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &EmailAuthReader{formats: a.formats},
		AuthInfo:           authInfo,
		Context:            params.Context,
		Client:             params.HTTPClient,
	}
	for _, opt := range opts {
		opt(op)
	}

	result, err := a.transport.Submit(op)
	if err != nil {
		return nil, err
	}
	success, ok := result.(*EmailAuthOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for EmailAuth: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
