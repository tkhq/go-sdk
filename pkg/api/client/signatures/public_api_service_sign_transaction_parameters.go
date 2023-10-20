// Code generated by go-swagger; DO NOT EDIT.

package signatures

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

// NewPublicAPIServiceSignTransactionParams creates a new PublicAPIServiceSignTransactionParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPublicAPIServiceSignTransactionParams() *PublicAPIServiceSignTransactionParams {
	return &PublicAPIServiceSignTransactionParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPublicAPIServiceSignTransactionParamsWithTimeout creates a new PublicAPIServiceSignTransactionParams object
// with the ability to set a timeout on a request.
func NewPublicAPIServiceSignTransactionParamsWithTimeout(timeout time.Duration) *PublicAPIServiceSignTransactionParams {
	return &PublicAPIServiceSignTransactionParams{
		timeout: timeout,
	}
}

// NewPublicAPIServiceSignTransactionParamsWithContext creates a new PublicAPIServiceSignTransactionParams object
// with the ability to set a context for a request.
func NewPublicAPIServiceSignTransactionParamsWithContext(ctx context.Context) *PublicAPIServiceSignTransactionParams {
	return &PublicAPIServiceSignTransactionParams{
		Context: ctx,
	}
}

// NewPublicAPIServiceSignTransactionParamsWithHTTPClient creates a new PublicAPIServiceSignTransactionParams object
// with the ability to set a custom HTTPClient for a request.
func NewPublicAPIServiceSignTransactionParamsWithHTTPClient(client *http.Client) *PublicAPIServiceSignTransactionParams {
	return &PublicAPIServiceSignTransactionParams{
		HTTPClient: client,
	}
}

/*
PublicAPIServiceSignTransactionParams contains all the parameters to send to the API endpoint

	for the public Api service sign transaction operation.

	Typically these are written to a http.Request.
*/
type PublicAPIServiceSignTransactionParams struct {

	// Body.
	Body *models.V1SignTransactionRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the public Api service sign transaction params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PublicAPIServiceSignTransactionParams) WithDefaults() *PublicAPIServiceSignTransactionParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the public Api service sign transaction params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PublicAPIServiceSignTransactionParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the public Api service sign transaction params
func (o *PublicAPIServiceSignTransactionParams) WithTimeout(timeout time.Duration) *PublicAPIServiceSignTransactionParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the public Api service sign transaction params
func (o *PublicAPIServiceSignTransactionParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the public Api service sign transaction params
func (o *PublicAPIServiceSignTransactionParams) WithContext(ctx context.Context) *PublicAPIServiceSignTransactionParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the public Api service sign transaction params
func (o *PublicAPIServiceSignTransactionParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the public Api service sign transaction params
func (o *PublicAPIServiceSignTransactionParams) WithHTTPClient(client *http.Client) *PublicAPIServiceSignTransactionParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the public Api service sign transaction params
func (o *PublicAPIServiceSignTransactionParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the public Api service sign transaction params
func (o *PublicAPIServiceSignTransactionParams) WithBody(body *models.V1SignTransactionRequest) *PublicAPIServiceSignTransactionParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the public Api service sign transaction params
func (o *PublicAPIServiceSignTransactionParams) SetBody(body *models.V1SignTransactionRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PublicAPIServiceSignTransactionParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
