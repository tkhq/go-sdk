// Code generated by go-swagger; DO NOT EDIT.

package organizations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new organizations API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for organizations API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	PublicAPIServiceCreateSubOrganization(params *PublicAPIServiceCreateSubOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceCreateSubOrganizationOK, error)

	PublicAPIServiceGetOrganization(params *PublicAPIServiceGetOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceGetOrganizationOK, error)

	PublicAPIServiceInitUserEmailRecovery(params *PublicAPIServiceInitUserEmailRecoveryParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceInitUserEmailRecoveryOK, error)

	PublicAPIServiceRecoverUser(params *PublicAPIServiceRecoverUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceRecoverUserOK, error)

	PublicAPIServiceRemoveOrganizationFeature(params *PublicAPIServiceRemoveOrganizationFeatureParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceRemoveOrganizationFeatureOK, error)

	PublicAPIServiceSetOrganizationFeature(params *PublicAPIServiceSetOrganizationFeatureParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceSetOrganizationFeatureOK, error)

	PublicAPIServiceUpdateAllowedOrigins(params *PublicAPIServiceUpdateAllowedOriginsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceUpdateAllowedOriginsOK, error)

	PublicAPIServiceUpdateRootQuorum(params *PublicAPIServiceUpdateRootQuorumParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceUpdateRootQuorumOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
PublicAPIServiceCreateSubOrganization creates sub organization

Create a new Sub-Organization
*/
func (a *Client) PublicAPIServiceCreateSubOrganization(params *PublicAPIServiceCreateSubOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceCreateSubOrganizationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceCreateSubOrganizationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_CreateSubOrganization",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/create_sub_organization",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceCreateSubOrganizationReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceCreateSubOrganizationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceCreateSubOrganizationDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PublicAPIServiceGetOrganization gets organization

Get details about an Organization
*/
func (a *Client) PublicAPIServiceGetOrganization(params *PublicAPIServiceGetOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceGetOrganizationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceGetOrganizationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_GetOrganization",
		Method:             "POST",
		PathPattern:        "/public/v1/query/get_organization",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceGetOrganizationReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceGetOrganizationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceGetOrganizationDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PublicAPIServiceInitUserEmailRecovery inits recovery

Initializes a new recovery
*/
func (a *Client) PublicAPIServiceInitUserEmailRecovery(params *PublicAPIServiceInitUserEmailRecoveryParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceInitUserEmailRecoveryOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceInitUserEmailRecoveryParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_InitUserEmailRecovery",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/init_user_email_recovery",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceInitUserEmailRecoveryReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceInitUserEmailRecoveryOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceInitUserEmailRecoveryDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PublicAPIServiceRecoverUser recovers a user

Completes the process of recovering a user by adding an authenticator
*/
func (a *Client) PublicAPIServiceRecoverUser(params *PublicAPIServiceRecoverUserParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceRecoverUserOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceRecoverUserParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_RecoverUser",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/recover_user",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceRecoverUserReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceRecoverUserOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceRecoverUserDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PublicAPIServiceRemoveOrganizationFeature removes organization feature

Removes an organization feature
*/
func (a *Client) PublicAPIServiceRemoveOrganizationFeature(params *PublicAPIServiceRemoveOrganizationFeatureParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceRemoveOrganizationFeatureOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceRemoveOrganizationFeatureParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_RemoveOrganizationFeature",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/remove_organization_feature",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceRemoveOrganizationFeatureReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceRemoveOrganizationFeatureOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceRemoveOrganizationFeatureDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PublicAPIServiceSetOrganizationFeature sets organization feature

Sets an organization feature
*/
func (a *Client) PublicAPIServiceSetOrganizationFeature(params *PublicAPIServiceSetOrganizationFeatureParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceSetOrganizationFeatureOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceSetOrganizationFeatureParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_SetOrganizationFeature",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/set_organization_feature",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceSetOrganizationFeatureReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceSetOrganizationFeatureOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceSetOrganizationFeatureDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PublicAPIServiceUpdateAllowedOrigins updates allowable origins

Update the allowable origins for credentials and requests
*/
func (a *Client) PublicAPIServiceUpdateAllowedOrigins(params *PublicAPIServiceUpdateAllowedOriginsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceUpdateAllowedOriginsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceUpdateAllowedOriginsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_UpdateAllowedOrigins",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/update_allowed_origins",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceUpdateAllowedOriginsReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceUpdateAllowedOriginsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceUpdateAllowedOriginsDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

/*
PublicAPIServiceUpdateRootQuorum updates root quorum

Set the threshold and members of the root quorum. This must be approved by the current root quorum.
*/
func (a *Client) PublicAPIServiceUpdateRootQuorum(params *PublicAPIServiceUpdateRootQuorumParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*PublicAPIServiceUpdateRootQuorumOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewPublicAPIServiceUpdateRootQuorumParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "PublicApiService_UpdateRootQuorum",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/update_root_quorum",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &PublicAPIServiceUpdateRootQuorumReader{formats: a.formats},
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
	success, ok := result.(*PublicAPIServiceUpdateRootQuorumOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	unexpectedSuccess := result.(*PublicAPIServiceUpdateRootQuorumDefault)
	return nil, runtime.NewAPIError("unexpected success response: content available as default response in error", unexpectedSuccess, unexpectedSuccess.Code())
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
