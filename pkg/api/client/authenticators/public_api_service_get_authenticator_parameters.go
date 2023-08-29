// Code generated by go-swagger; DO NOT EDIT.

package authenticators

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

// NewPublicAPIServiceGetAuthenticatorParams creates a new PublicAPIServiceGetAuthenticatorParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPublicAPIServiceGetAuthenticatorParams() *PublicAPIServiceGetAuthenticatorParams {
	return &PublicAPIServiceGetAuthenticatorParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPublicAPIServiceGetAuthenticatorParamsWithTimeout creates a new PublicAPIServiceGetAuthenticatorParams object
// with the ability to set a timeout on a request.
func NewPublicAPIServiceGetAuthenticatorParamsWithTimeout(timeout time.Duration) *PublicAPIServiceGetAuthenticatorParams {
	return &PublicAPIServiceGetAuthenticatorParams{
		timeout: timeout,
	}
}

// NewPublicAPIServiceGetAuthenticatorParamsWithContext creates a new PublicAPIServiceGetAuthenticatorParams object
// with the ability to set a context for a request.
func NewPublicAPIServiceGetAuthenticatorParamsWithContext(ctx context.Context) *PublicAPIServiceGetAuthenticatorParams {
	return &PublicAPIServiceGetAuthenticatorParams{
		Context: ctx,
	}
}

// NewPublicAPIServiceGetAuthenticatorParamsWithHTTPClient creates a new PublicAPIServiceGetAuthenticatorParams object
// with the ability to set a custom HTTPClient for a request.
func NewPublicAPIServiceGetAuthenticatorParamsWithHTTPClient(client *http.Client) *PublicAPIServiceGetAuthenticatorParams {
	return &PublicAPIServiceGetAuthenticatorParams{
		HTTPClient: client,
	}
}

/*
PublicAPIServiceGetAuthenticatorParams contains all the parameters to send to the API endpoint

	for the public Api service get authenticator operation.

	Typically these are written to a http.Request.
*/
type PublicAPIServiceGetAuthenticatorParams struct {

	// Body.
	Body *models.V1GetAuthenticatorRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the public Api service get authenticator params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PublicAPIServiceGetAuthenticatorParams) WithDefaults() *PublicAPIServiceGetAuthenticatorParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the public Api service get authenticator params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PublicAPIServiceGetAuthenticatorParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the public Api service get authenticator params
func (o *PublicAPIServiceGetAuthenticatorParams) WithTimeout(timeout time.Duration) *PublicAPIServiceGetAuthenticatorParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the public Api service get authenticator params
func (o *PublicAPIServiceGetAuthenticatorParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the public Api service get authenticator params
func (o *PublicAPIServiceGetAuthenticatorParams) WithContext(ctx context.Context) *PublicAPIServiceGetAuthenticatorParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the public Api service get authenticator params
func (o *PublicAPIServiceGetAuthenticatorParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the public Api service get authenticator params
func (o *PublicAPIServiceGetAuthenticatorParams) WithHTTPClient(client *http.Client) *PublicAPIServiceGetAuthenticatorParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the public Api service get authenticator params
func (o *PublicAPIServiceGetAuthenticatorParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the public Api service get authenticator params
func (o *PublicAPIServiceGetAuthenticatorParams) WithBody(body *models.V1GetAuthenticatorRequest) *PublicAPIServiceGetAuthenticatorParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the public Api service get authenticator params
func (o *PublicAPIServiceGetAuthenticatorParams) SetBody(body *models.V1GetAuthenticatorRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PublicAPIServiceGetAuthenticatorParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
