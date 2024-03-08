// Code generated by go-swagger; DO NOT EDIT.

package organizations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

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
	CreateSubOrganization(params *CreateSubOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateSubOrganizationOK, error)

	GetSubOrgIds(params *GetSubOrgIdsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetSubOrgIdsOK, error)

	UpdateRootQuorum(params *UpdateRootQuorumParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateRootQuorumOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
CreateSubOrganization creates sub organization

Create a new Sub-Organization
*/
func (a *Client) CreateSubOrganization(params *CreateSubOrganizationParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateSubOrganizationOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateSubOrganizationParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateSubOrganization",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/create_sub_organization",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateSubOrganizationReader{formats: a.formats},
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
	success, ok := result.(*CreateSubOrganizationOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreateSubOrganization: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetSubOrgIds gets suborgs

Get all suborg IDs associated given a parent org ID and an optional filter.
*/
func (a *Client) GetSubOrgIds(params *GetSubOrgIdsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetSubOrgIdsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetSubOrgIdsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetSubOrgIds",
		Method:             "POST",
		PathPattern:        "/public/v1/query/list_suborgs",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetSubOrgIdsReader{formats: a.formats},
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
	success, ok := result.(*GetSubOrgIdsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetSubOrgIds: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
UpdateRootQuorum updates root quorum

Set the threshold and members of the root quorum. This must be approved by the current root quorum.
*/
func (a *Client) UpdateRootQuorum(params *UpdateRootQuorumParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*UpdateRootQuorumOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewUpdateRootQuorumParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "UpdateRootQuorum",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/update_root_quorum",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &UpdateRootQuorumReader{formats: a.formats},
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
	success, ok := result.(*UpdateRootQuorumOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for UpdateRootQuorum: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
