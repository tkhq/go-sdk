// Code generated by go-swagger; DO NOT EDIT.

package user_recovery

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new user recovery API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for user recovery API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	InitUserEmailRecovery(params *InitUserEmailRecoveryParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*InitUserEmailRecoveryOK, error)

	RecoverUser(params *RecoverUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RecoverUserOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
InitUserEmailRecovery inits email recovery

Initializes a new email recovery
*/
func (a *Client) InitUserEmailRecovery(params *InitUserEmailRecoveryParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*InitUserEmailRecoveryOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewInitUserEmailRecoveryParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "InitUserEmailRecovery",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/init_user_email_recovery",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &InitUserEmailRecoveryReader{formats: a.formats},
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
	success, ok := result.(*InitUserEmailRecoveryOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for InitUserEmailRecovery: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
RecoverUser recovers a user

Completes the process of recovering a user by adding an authenticator
*/
func (a *Client) RecoverUser(params *RecoverUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*RecoverUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewRecoverUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "RecoverUser",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/recover_user",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &RecoverUserReader{formats: a.formats},
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
	success, ok := result.(*RecoverUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for RecoverUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
