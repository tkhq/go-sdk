// Code generated by go-swagger; DO NOT EDIT.

package wallets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new wallets API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for wallets API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientOption is the option for Client methods
type ClientOption func(*runtime.ClientOperation)

// ClientService is the interface for Client methods
type ClientService interface {
	CreateWallet(params *CreateWalletParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateWalletOK, error)

	CreateWalletAccounts(params *CreateWalletAccountsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateWalletAccountsOK, error)

	DeleteWallets(params *DeleteWalletsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteWalletsOK, error)

	ExportWallet(params *ExportWalletParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ExportWalletOK, error)

	ExportWalletAccount(params *ExportWalletAccountParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ExportWalletAccountOK, error)

	GetWallet(params *GetWalletParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetWalletOK, error)

	GetWalletAccounts(params *GetWalletAccountsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetWalletAccountsOK, error)

	GetWallets(params *GetWalletsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetWalletsOK, error)

	ImportWallet(params *ImportWalletParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ImportWalletOK, error)

	InitImportWallet(params *InitImportWalletParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*InitImportWalletOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
CreateWallet creates wallet

Create a Wallet and derive addresses
*/
func (a *Client) CreateWallet(params *CreateWalletParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateWalletOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateWalletParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateWallet",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/create_wallet",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateWalletReader{formats: a.formats},
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
	success, ok := result.(*CreateWalletOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreateWallet: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
CreateWalletAccounts creates wallet accounts

Derive additional addresses using an existing wallet
*/
func (a *Client) CreateWalletAccounts(params *CreateWalletAccountsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*CreateWalletAccountsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewCreateWalletAccountsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "CreateWalletAccounts",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/create_wallet_accounts",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &CreateWalletAccountsReader{formats: a.formats},
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
	success, ok := result.(*CreateWalletAccountsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for CreateWalletAccounts: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
DeleteWallets deletes organization wallets

Deletes wallets for an organization
*/
func (a *Client) DeleteWallets(params *DeleteWalletsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*DeleteWalletsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewDeleteWalletsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "DeleteWallets",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/delete_wallets",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &DeleteWalletsReader{formats: a.formats},
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
	success, ok := result.(*DeleteWalletsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for DeleteWallets: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExportWallet exports wallet

Exports a Wallet
*/
func (a *Client) ExportWallet(params *ExportWalletParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ExportWalletOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExportWalletParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ExportWallet",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/export_wallet",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExportWalletReader{formats: a.formats},
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
	success, ok := result.(*ExportWalletOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ExportWallet: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ExportWalletAccount exports wallet account

Exports a Wallet Account
*/
func (a *Client) ExportWalletAccount(params *ExportWalletAccountParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ExportWalletAccountOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewExportWalletAccountParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ExportWalletAccount",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/export_wallet_account",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ExportWalletAccountReader{formats: a.formats},
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
	success, ok := result.(*ExportWalletAccountOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ExportWalletAccount: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetWallet gets wallet

Get details about a Wallet
*/
func (a *Client) GetWallet(params *GetWalletParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetWalletOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetWalletParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetWallet",
		Method:             "POST",
		PathPattern:        "/public/v1/query/get_wallet",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetWalletReader{formats: a.formats},
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
	success, ok := result.(*GetWalletOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetWallet: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetWalletAccounts lists wallets accounts

List all Accounts wirhin a Wallet
*/
func (a *Client) GetWalletAccounts(params *GetWalletAccountsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetWalletAccountsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetWalletAccountsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetWalletAccounts",
		Method:             "POST",
		PathPattern:        "/public/v1/query/list_wallet_accounts",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetWalletAccountsReader{formats: a.formats},
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
	success, ok := result.(*GetWalletAccountsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetWalletAccounts: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
GetWallets lists wallets

List all Wallets within an Organization
*/
func (a *Client) GetWallets(params *GetWalletsParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*GetWalletsOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewGetWalletsParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "GetWallets",
		Method:             "POST",
		PathPattern:        "/public/v1/query/list_wallets",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &GetWalletsReader{formats: a.formats},
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
	success, ok := result.(*GetWalletsOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for GetWallets: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
ImportWallet imports wallet

Imports a wallet
*/
func (a *Client) ImportWallet(params *ImportWalletParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*ImportWalletOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewImportWalletParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "ImportWallet",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/import_wallet",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &ImportWalletReader{formats: a.formats},
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
	success, ok := result.(*ImportWalletOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for ImportWallet: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
InitImportWallet inits import wallet

Initializes a new wallet import
*/
func (a *Client) InitImportWallet(params *InitImportWalletParams, authInfo runtime.ClientAuthInfoWriter, opts ...ClientOption) (*InitImportWalletOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewInitImportWalletParams()
	}
	op := &runtime.ClientOperation{
		ID:                 "InitImportWallet",
		Method:             "POST",
		PathPattern:        "/public/v1/submit/init_import_wallet",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"https"},
		Params:             params,
		Reader:             &InitImportWalletReader{formats: a.formats},
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
	success, ok := result.(*InitImportWalletOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for InitImportWallet: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
