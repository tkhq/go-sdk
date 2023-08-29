// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new users API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for users API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	PublicAPIServiceCreateAPIOnlyUsers(params *PublicAPIServiceCreateAPIOnlyUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceCreateAPIOnlyUsersOK, error)

	PublicAPIServiceCreateUsers(params *PublicAPIServiceCreateUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceCreateUsersOK, error)

	PublicAPIServiceGetUser(params *PublicAPIServiceGetUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceGetUserOK, error)

	PublicAPIServiceGetUsers(params *PublicAPIServiceGetUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceGetUsersOK, error)

	PublicAPIServiceUpdateUser(params *PublicAPIServiceUpdateUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceUpdateUserOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
PublicAPIServiceCreateAPIOnlyUsers creates API only users

Create API-only Users in an existing Organization
*/
func (a *Client) PublicAPIServiceCreateAPIOnlyUsers(params *PublicAPIServiceCreateAPIOnlyUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceCreateAPIOnlyUsersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceCreateAPIOnlyUsersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_CreateApiOnlyUsers",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/create_api_only_users",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceCreateAPIOnlyUsersReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceCreateAPIOnlyUsersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceCreateAPIOnlyUsersDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PublicAPIServiceCreateUsers creates users

Create Users in an existing Organization
*/
func (a *Client) PublicAPIServiceCreateUsers(params *PublicAPIServiceCreateUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceCreateUsersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceCreateUsersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_CreateUsers",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/create_users",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceCreateUsersReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceCreateUsersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceCreateUsersDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PublicAPIServiceGetUser gets user

Get details about a User
*/
func (a *Client) PublicAPIServiceGetUser(params *PublicAPIServiceGetUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceGetUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceGetUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_GetUser",
		Method:             "POST",
		PathPattern:        "/public/v1/query/get_user",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceGetUserReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceGetUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceGetUserDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PublicAPIServiceGetUsers lists users

List all Users within an Organization
*/
func (a *Client) PublicAPIServiceGetUsers(params *PublicAPIServiceGetUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceGetUsersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceGetUsersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_GetUsers",
		Method:             "POST",
		PathPattern:        "/public/v1/query/list_users",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceGetUsersReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceGetUsersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceGetUsersDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PublicAPIServiceUpdateUser updates user

Update a User in an existing Organization
*/
func (a *Client) PublicAPIServiceUpdateUser(params *PublicAPIServiceUpdateUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceUpdateUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceUpdateUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_UpdateUser",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/update_user",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceUpdateUserReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceUpdateUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceUpdateUserDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
