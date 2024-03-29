// Code generated by go-swagger; DO NOT EDIT.

package activities

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new activities API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for activities API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	GetActivities(params *GetActivitiesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetActivitiesOK, error)

	GetActivity(params *GetActivityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetActivityOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
GetActivities lists activities

List all Activities within an Organization
*/
func (a *Client) GetActivities(params *GetActivitiesParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetActivitiesOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetActivitiesParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetActivities",
		Method:             "POST",
		PathPattern:        "/public/v1/query/list_activities",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetActivitiesReader{formats: a.formats},
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
	success, ok := result.(*GetActivitiesOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetActivities: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetActivity gets activity

Get details about an Activity
*/
func (a *Client) GetActivity(params *GetActivityParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetActivityOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetActivityParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetActivity",
		Method:             "POST",
		PathPattern:        "/public/v1/query/get_activity",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetActivityReader{formats: a.formats},
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
	success, ok := result.(*GetActivityOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetActivity: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
