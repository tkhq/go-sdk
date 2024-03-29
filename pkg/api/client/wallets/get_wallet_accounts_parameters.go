// Code generated by go-swagger; DO NOT EDIT.

package wallets

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// NewGetWalletAccountsParams creates a new GetWalletAccountsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetWalletAccountsParams() *GetWalletAccountsParams {
	return &GetWalletAccountsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetWalletAccountsParamsWithTimeout creates a new GetWalletAccountsParams object
// with the ability to set a timeout on a request.
func NewGetWalletAccountsParamsWithTimeout(timeout time.Duration) *GetWalletAccountsParams {
	return &GetWalletAccountsParams{
		timeout: timeout,
	}
}

// NewGetWalletAccountsParamsWithContext creates a new GetWalletAccountsParams object
// with the ability to set a context for a request.
func NewGetWalletAccountsParamsWithContext(ctx context.Context) *GetWalletAccountsParams {
	return &GetWalletAccountsParams{
		Context: ctx,
	}
}

// NewGetWalletAccountsParamsWithHTTPClient creates a new GetWalletAccountsParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetWalletAccountsParamsWithHTTPClient(client *http.Client) *GetWalletAccountsParams {
	return &GetWalletAccountsParams{
		HTTPClient: client,
	}
}

/*
GetWalletAccountsParams contains all the parameters to send to the API endpoint

	for the get wallet accounts operation.

	Typically these are written to a http.Request.
*/
type GetWalletAccountsParams struct {

	// Body.
	Body *models.GetWalletAccountsRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get wallet accounts params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetWalletAccountsParams) WithDefaults() *GetWalletAccountsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get wallet accounts params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetWalletAccountsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get wallet accounts params
func (o *GetWalletAccountsParams) WithTimeout(timeout time.Duration) *GetWalletAccountsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get wallet accounts params
func (o *GetWalletAccountsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get wallet accounts params
func (o *GetWalletAccountsParams) WithContext(ctx context.Context) *GetWalletAccountsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get wallet accounts params
func (o *GetWalletAccountsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get wallet accounts params
func (o *GetWalletAccountsParams) WithHTTPClient(client *http.Client) *GetWalletAccountsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get wallet accounts params
func (o *GetWalletAccountsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the get wallet accounts params
func (o *GetWalletAccountsParams) WithBody(body *models.GetWalletAccountsRequest) *GetWalletAccountsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the get wallet accounts params
func (o *GetWalletAccountsParams) SetBody(body *models.GetWalletAccountsRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *GetWalletAccountsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error
	if o.Body != nil {
		if err := r.SetBodyParam(o.Body); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
