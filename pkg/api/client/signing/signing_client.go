// Code generated by go-swagger; DO NOT EDIT.

package signing

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new signing API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new signing API client with basic auth credentials.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - user: user for basic authentication header.
// - password: password for basic authentication header.
func NewClientWithBasicAuth(host, basePath, scheme, user, password string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BasicAuth(user, password)
	return &Client{transport: transport, formats: strfmt.Default}
}

// New creates a new signing API client with a bearer token for authentication.
// It takes the following parameters:
// - host: http host (github.com).
// - basePath: any base path for the API client ("/v1", "/v3").
// - scheme: http scheme ("http", "https").
// - bearerToken: bearer token for Bearer authentication header.
func NewClientWithBearerToken(host, basePath, scheme, bearerToken string) ClientService {
	transport := httptransport.New(host, basePath, []string{scheme})
	transport.DefaultAuthentication = httptransport.BearerToken(bearerToken)
	return &Client{transport: transport, formats: strfmt.Default}
}

/*
Client for signing API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	SignRawPayload(params *SignRawPayloadParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SignRawPayloadOK, error)

	SignRawPayloads(params *SignRawPayloadsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SignRawPayloadsOK, error)

	SignTransaction(params *SignTransactionParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SignTransactionOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
SignRawPayload signs raw payload

Sign a raw payload
*/
func (a *Client) SignRawPayload(params *SignRawPayloadParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SignRawPayloadOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSignRawPayloadParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "SignRawPayload",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/sign_raw_payload",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SignRawPayloadReader{formats: a.formats},
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
	success, ok := result.(*SignRawPayloadOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for SignRawPayload: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
SignRawPayloads signs raw payloads

Sign multiple raw payloads with the same signing parameters
*/
func (a *Client) SignRawPayloads(params *SignRawPayloadsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SignRawPayloadsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSignRawPayloadsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "SignRawPayloads",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/sign_raw_payloads",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SignRawPayloadsReader{formats: a.formats},
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
	success, ok := result.(*SignRawPayloadsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for SignRawPayloads: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
SignTransaction signs transaction

Sign a transaction
*/
func (a *Client) SignTransaction(params *SignTransactionParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*SignTransactionOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewSignTransactionParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "SignTransaction",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/sign_transaction",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &SignTransactionReader{formats: a.formats},
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
	success, ok := result.(*SignTransactionOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for SignTransaction: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
