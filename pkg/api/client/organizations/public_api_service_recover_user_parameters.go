// Code generated by go-swagger; DO NOT EDIT.

package organizations

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

// NewPublicAPIServiceRecoverUserParams creates a new PublicAPIServiceRecoverUserParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPublicAPIServiceRecoverUserParams() *PublicAPIServiceRecoverUserParams {
	return &PublicAPIServiceRecoverUserParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPublicAPIServiceRecoverUserParamsWithTimeout creates a new PublicAPIServiceRecoverUserParams object
// with the ability to set a timeout on a request.
func NewPublicAPIServiceRecoverUserParamsWithTimeout(timeout time.Duration) *PublicAPIServiceRecoverUserParams {
	return &PublicAPIServiceRecoverUserParams{
		timeout: timeout,
	}
}

// NewPublicAPIServiceRecoverUserParamsWithContext creates a new PublicAPIServiceRecoverUserParams object
// with the ability to set a context for a request.
func NewPublicAPIServiceRecoverUserParamsWithContext(ctx context.Context) *PublicAPIServiceRecoverUserParams {
	return &PublicAPIServiceRecoverUserParams{
		Context: ctx,
	}
}

// NewPublicAPIServiceRecoverUserParamsWithHTTPClient creates a new PublicAPIServiceRecoverUserParams object
// with the ability to set a custom HTTPClient for a request.
func NewPublicAPIServiceRecoverUserParamsWithHTTPClient(client *http.Client) *PublicAPIServiceRecoverUserParams {
	return &PublicAPIServiceRecoverUserParams{
		HTTPClient: client,
	}
}

/*
PublicAPIServiceRecoverUserParams contains all the parameters to send to the API endpoint

	for the public Api service recover user operation.

	Typically these are written to a http.Request.
*/
type PublicAPIServiceRecoverUserParams struct {

	// Body.
	Body *models.V1RecoverUserRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the public Api service recover user params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PublicAPIServiceRecoverUserParams) WithDefaults() *PublicAPIServiceRecoverUserParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the public Api service recover user params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PublicAPIServiceRecoverUserParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the public Api service recover user params
func (o *PublicAPIServiceRecoverUserParams) WithTimeout(timeout time.Duration) *PublicAPIServiceRecoverUserParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the public Api service recover user params
func (o *PublicAPIServiceRecoverUserParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the public Api service recover user params
func (o *PublicAPIServiceRecoverUserParams) WithContext(ctx context.Context) *PublicAPIServiceRecoverUserParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the public Api service recover user params
func (o *PublicAPIServiceRecoverUserParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the public Api service recover user params
func (o *PublicAPIServiceRecoverUserParams) WithHTTPClient(client *http.Client) *PublicAPIServiceRecoverUserParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the public Api service recover user params
func (o *PublicAPIServiceRecoverUserParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the public Api service recover user params
func (o *PublicAPIServiceRecoverUserParams) WithBody(body *models.V1RecoverUserRequest) *PublicAPIServiceRecoverUserParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the public Api service recover user params
func (o *PublicAPIServiceRecoverUserParams) SetBody(body *models.V1RecoverUserRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PublicAPIServiceRecoverUserParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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