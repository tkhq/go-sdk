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

// NewGetPrivateKeyParams creates a new GetPrivateKeyParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetPrivateKeyParams() *GetPrivateKeyParams {
	return &GetPrivateKeyParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetPrivateKeyParamsWithTimeout creates a new GetPrivateKeyParams object
// with the ability to set a timeout on a request.
func NewGetPrivateKeyParamsWithTimeout(timeout time.Duration) *GetPrivateKeyParams {
	return &GetPrivateKeyParams{
		timeout: timeout,
	}
}

// NewGetPrivateKeyParamsWithContext creates a new GetPrivateKeyParams object
// with the ability to set a context for a request.
func NewGetPrivateKeyParamsWithContext(ctx context.Context) *GetPrivateKeyParams {
	return &GetPrivateKeyParams{
		Context: ctx,
	}
}

// NewGetPrivateKeyParamsWithHTTPClient creates a new GetPrivateKeyParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetPrivateKeyParamsWithHTTPClient(client *http.Client) *GetPrivateKeyParams {
	return &GetPrivateKeyParams{
		HTTPClient: client,
	}
}

/*
GetPrivateKeyParams contains all the parameters to send to the API endpoint

	for the get private key operation.

	Typically these are written to a http.Request.
*/
type GetPrivateKeyParams struct {

	// Body.
	Body *models.GetPrivateKeyRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get private key params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetPrivateKeyParams) WithDefaults() *GetPrivateKeyParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get private key params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetPrivateKeyParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get private key params
func (o *GetPrivateKeyParams) WithTimeout(timeout time.Duration) *GetPrivateKeyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get private key params
func (o *GetPrivateKeyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get private key params
func (o *GetPrivateKeyParams) WithContext(ctx context.Context) *GetPrivateKeyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get private key params
func (o *GetPrivateKeyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get private key params
func (o *GetPrivateKeyParams) WithHTTPClient(client *http.Client) *GetPrivateKeyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get private key params
func (o *GetPrivateKeyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the get private key params
func (o *GetPrivateKeyParams) WithBody(body *models.GetPrivateKeyRequest) *GetPrivateKeyParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the get private key params
func (o *GetPrivateKeyParams) SetBody(body *models.GetPrivateKeyRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *GetPrivateKeyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
