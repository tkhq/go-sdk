// Code generated by go-swagger; DO NOT EDIT.

package api_keys

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new api keys API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for api keys API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	PublicAPIServiceCreateAPIKeys(params *PublicAPIServiceCreateAPIKeysParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceCreateAPIKeysOK, error)

	PublicAPIServiceDeleteAPIKeys(params *PublicAPIServiceDeleteAPIKeysParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceDeleteAPIKeysOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
PublicAPIServiceCreateAPIKeys creates API keys

Add api keys to an existing User
*/
func (a *Client) PublicAPIServiceCreateAPIKeys(params *PublicAPIServiceCreateAPIKeysParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceCreateAPIKeysOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceCreateAPIKeysParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_CreateApiKeys",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/create_api_keys",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceCreateAPIKeysReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceCreateAPIKeysOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceCreateAPIKeysDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PublicAPIServiceDeleteAPIKeys deletes API keys

Remove api keys from a User
*/
func (a *Client) PublicAPIServiceDeleteAPIKeys(params *PublicAPIServiceDeleteAPIKeysParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceDeleteAPIKeysOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceDeleteAPIKeysParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_DeleteApiKeys",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/delete_api_keys",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceDeleteAPIKeysReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceDeleteAPIKeysOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceDeleteAPIKeysDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
