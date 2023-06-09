// Code generated by go-swagger; DO NOT EDIT.

package private_keys

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

// NewPublicAPIServiceSignRawPayloadParams creates a new PublicAPIServiceSignRawPayloadParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPublicAPIServiceSignRawPayloadParams() *PublicAPIServiceSignRawPayloadParams {
	return &PublicAPIServiceSignRawPayloadParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPublicAPIServiceSignRawPayloadParamsWithTimeout creates a new PublicAPIServiceSignRawPayloadParams object
// with the ability to set a timeout on a request.
func NewPublicAPIServiceSignRawPayloadParamsWithTimeout(timeout time.Duration) *PublicAPIServiceSignRawPayloadParams {
	return &PublicAPIServiceSignRawPayloadParams{
		timeout: timeout,
	}
}

// NewPublicAPIServiceSignRawPayloadParamsWithContext creates a new PublicAPIServiceSignRawPayloadParams object
// with the ability to set a context for a request.
func NewPublicAPIServiceSignRawPayloadParamsWithContext(ctx context.Context) *PublicAPIServiceSignRawPayloadParams {
	return &PublicAPIServiceSignRawPayloadParams{
		Context: ctx,
	}
}

// NewPublicAPIServiceSignRawPayloadParamsWithHTTPClient creates a new PublicAPIServiceSignRawPayloadParams object
// with the ability to set a custom HTTPClient for a request.
func NewPublicAPIServiceSignRawPayloadParamsWithHTTPClient(client *http.Client) *PublicAPIServiceSignRawPayloadParams {
	return &PublicAPIServiceSignRawPayloadParams{
		HTTPClient: client,
	}
}

/*
PublicAPIServiceSignRawPayloadParams contains all the parameters to send to the API endpoint

	for the public Api service sign raw payload operation.

	Typically these are written to a http.Request.
*/
type PublicAPIServiceSignRawPayloadParams struct {

	// Body.
	Body *models.V1SignRawPayloadRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the public Api service sign raw payload params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PublicAPIServiceSignRawPayloadParams) WithDefaults() *PublicAPIServiceSignRawPayloadParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the public Api service sign raw payload params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PublicAPIServiceSignRawPayloadParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the public Api service sign raw payload params
func (o *PublicAPIServiceSignRawPayloadParams) WithTimeout(timeout time.Duration) *PublicAPIServiceSignRawPayloadParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the public Api service sign raw payload params
func (o *PublicAPIServiceSignRawPayloadParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the public Api service sign raw payload params
func (o *PublicAPIServiceSignRawPayloadParams) WithContext(ctx context.Context) *PublicAPIServiceSignRawPayloadParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the public Api service sign raw payload params
func (o *PublicAPIServiceSignRawPayloadParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the public Api service sign raw payload params
func (o *PublicAPIServiceSignRawPayloadParams) WithHTTPClient(client *http.Client) *PublicAPIServiceSignRawPayloadParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the public Api service sign raw payload params
func (o *PublicAPIServiceSignRawPayloadParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the public Api service sign raw payload params
func (o *PublicAPIServiceSignRawPayloadParams) WithBody(body *models.V1SignRawPayloadRequest) *PublicAPIServiceSignRawPayloadParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the public Api service sign raw payload params
func (o *PublicAPIServiceSignRawPayloadParams) SetBody(body *models.V1SignRawPayloadRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PublicAPIServiceSignRawPayloadParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
