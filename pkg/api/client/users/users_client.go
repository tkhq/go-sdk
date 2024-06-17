// Code generated by go-swagger; DO NOT EDIT.

package users

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	httptransport "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// New creates a new users API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

// New creates a new users API client with basic auth credentials.
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

// New creates a new users API client with a bearer token for authentication.
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
Client for users API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption may be used to customize the behavior of Client methods.
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateOauthProviders(params *CreateOauthProvidersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateOauthProvidersOK, error)

	CreateUsers(params *CreateUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateUsersOK, error)

	DeleteOauthProviders(params *DeleteOauthProvidersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteOauthProvidersOK, error)

	DeleteUsers(params *DeleteUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteUsersOK, error)

	GetOauthProviders(params *GetOauthProvidersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetOauthProvidersOK, error)

	GetUser(params *GetUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetUserOK, error)

	GetUsers(params *GetUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetUsersOK, error)

	Oauth(params *OauthParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*OauthOK, error)

	UpdateUser(params *UpdateUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateUserOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
CreateOauthProviders creates oauth providers

Creates Oauth providers for a specified user - BETA
*/
func (a *Client) CreateOauthProviders(params *CreateOauthProvidersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateOauthProvidersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateOauthProvidersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateOauthProviders",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/create_oauth_providers",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateOauthProvidersReader{formats: a.formats},
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
	success, ok := result.(*CreateOauthProvidersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreateOauthProviders: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CreateUsers creates users

Create Users in an existing Organization
*/
func (a *Client) CreateUsers(params *CreateUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateUsersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateUsersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateUsers",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/create_users",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateUsersReader{formats: a.formats},
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
	success, ok := result.(*CreateUsersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreateUsers: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteOauthProviders deletes oauth providers

Removes Oauth providers for a specified user - BETA
*/
func (a *Client) DeleteOauthProviders(params *DeleteOauthProvidersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteOauthProvidersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteOauthProvidersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteOauthProviders",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/delete_oauth_providers",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteOauthProvidersReader{formats: a.formats},
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
	success, ok := result.(*DeleteOauthProvidersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteOauthProviders: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteUsers deletes users

Delete Users within an Organization
*/
func (a *Client) DeleteUsers(params *DeleteUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteUsersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteUsersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteUsers",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/delete_users",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteUsersReader{formats: a.formats},
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
	success, ok := result.(*DeleteUsersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteUsers: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetOauthProviders gets oauth providers

Get details about Oauth providers for a user
*/
func (a *Client) GetOauthProviders(params *GetOauthProvidersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetOauthProvidersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetOauthProvidersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetOauthProviders",
		Method:             "POST",
		PathPattern:        "/public/v1/query/get_oauth_providers",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetOauthProvidersReader{formats: a.formats},
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
	success, ok := result.(*GetOauthProvidersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetOauthProviders: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetUser gets user

Get details about a User
*/
func (a *Client) GetUser(params *GetUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetUser",
		Method:             "POST",
		PathPattern:        "/public/v1/query/get_user",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetUserReader{formats: a.formats},
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
	success, ok := result.(*GetUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetUsers lists users

List all Users within an Organization
*/
func (a *Client) GetUsers(params *GetUsersParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetUsersOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetUsersParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetUsers",
		Method:             "POST",
		PathPattern:        "/public/v1/query/list_users",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetUsersReader{formats: a.formats},
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
	success, ok := result.(*GetUsersOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetUsers: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
Oauth oauths

Authenticate a user with an Oidc token (Oauth) - BETA
*/
func (a *Client) Oauth(params *OauthParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*OauthOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewOauthParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "Oauth",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/oauth",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &OauthReader{formats: a.formats},
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
	success, ok := result.(*OauthOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for Oauth: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpdateUser updates user

Update a User in an existing Organization
*/
func (a *Client) UpdateUser(params *UpdateUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "UpdateUser",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/update_user",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateUserReader{formats: a.formats},
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
	success, ok := result.(*UpdateUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for UpdateUser: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
