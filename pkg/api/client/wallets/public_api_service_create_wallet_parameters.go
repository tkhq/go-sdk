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

// NewPublicAPIServiceCreateWalletParams creates a new PublicAPIServiceCreateWalletParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPublicAPIServiceCreateWalletParams() *PublicAPIServiceCreateWalletParams {
	return &PublicAPIServiceCreateWalletParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPublicAPIServiceCreateWalletParamsWithTimeout creates a new PublicAPIServiceCreateWalletParams object
// with the ability to set a timeout on a request.
func NewPublicAPIServiceCreateWalletParamsWithTimeout(timeout time.Duration) *PublicAPIServiceCreateWalletParams {
	return &PublicAPIServiceCreateWalletParams{
		timeout: timeout,
	}
}

// NewPublicAPIServiceCreateWalletParamsWithContext creates a new PublicAPIServiceCreateWalletParams object
// with the ability to set a context for a request.
func NewPublicAPIServiceCreateWalletParamsWithContext(ctx context.Context) *PublicAPIServiceCreateWalletParams {
	return &PublicAPIServiceCreateWalletParams{
		Context: ctx,
	}
}

// NewPublicAPIServiceCreateWalletParamsWithHTTPClient creates a new PublicAPIServiceCreateWalletParams object
// with the ability to set a custom HTTPClient for a request.
func NewPublicAPIServiceCreateWalletParamsWithHTTPClient(client *http.Client) *PublicAPIServiceCreateWalletParams {
	return &PublicAPIServiceCreateWalletParams{
		HTTPClient: client,
	}
}

/*
PublicAPIServiceCreateWalletParams contains all the parameters to send to the API endpoint

	for the public Api service create wallet operation.

	Typically these are written to a http.Request.
*/
type PublicAPIServiceCreateWalletParams struct {

	// Body.
	Body *models.V1CreateWalletRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the public Api service create wallet params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PublicAPIServiceCreateWalletParams) WithDefaults() *PublicAPIServiceCreateWalletParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the public Api service create wallet params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PublicAPIServiceCreateWalletParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the public Api service create wallet params
func (o *PublicAPIServiceCreateWalletParams) WithTimeout(timeout time.Duration) *PublicAPIServiceCreateWalletParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the public Api service create wallet params
func (o *PublicAPIServiceCreateWalletParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the public Api service create wallet params
func (o *PublicAPIServiceCreateWalletParams) WithContext(ctx context.Context) *PublicAPIServiceCreateWalletParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the public Api service create wallet params
func (o *PublicAPIServiceCreateWalletParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the public Api service create wallet params
func (o *PublicAPIServiceCreateWalletParams) WithHTTPClient(client *http.Client) *PublicAPIServiceCreateWalletParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the public Api service create wallet params
func (o *PublicAPIServiceCreateWalletParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the public Api service create wallet params
func (o *PublicAPIServiceCreateWalletParams) WithBody(body *models.V1CreateWalletRequest) *PublicAPIServiceCreateWalletParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the public Api service create wallet params
func (o *PublicAPIServiceCreateWalletParams) SetBody(body *models.V1CreateWalletRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PublicAPIServiceCreateWalletParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
