// Code generated by go-swagger; DO NOT EDIT.

package api_keys

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

// NewGetAPIKeysParams creates a new GetAPIKeysParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetAPIKeysParams() *GetAPIKeysParams {
	return &GetAPIKeysParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetAPIKeysParamsWithTimeout creates a new GetAPIKeysParams object
// with the ability to set a timeout on a request.
func NewGetAPIKeysParamsWithTimeout(timeout time.Duration) *GetAPIKeysParams {
	return &GetAPIKeysParams{
		timeout: timeout,
	}
}

// NewGetAPIKeysParamsWithContext creates a new GetAPIKeysParams object
// with the ability to set a context for a request.
func NewGetAPIKeysParamsWithContext(ctx context.Context) *GetAPIKeysParams {
	return &GetAPIKeysParams{
		Context: ctx,
	}
}

// NewGetAPIKeysParamsWithHTTPClient creates a new GetAPIKeysParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetAPIKeysParamsWithHTTPClient(client *http.Client) *GetAPIKeysParams {
	return &GetAPIKeysParams{
		HTTPClient: client,
	}
}

/*
GetAPIKeysParams contains all the parameters to send to the API endpoint

	for the get Api keys operation.

	Typically these are written to a http.Request.
*/
type GetAPIKeysParams struct {

	// Body.
	Body *models.GetAPIKeysRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get Api keys params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIKeysParams) WithDefaults() *GetAPIKeysParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get Api keys params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetAPIKeysParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get Api keys params
func (o *GetAPIKeysParams) WithTimeout(timeout time.Duration) *GetAPIKeysParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get Api keys params
func (o *GetAPIKeysParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get Api keys params
func (o *GetAPIKeysParams) WithContext(ctx context.Context) *GetAPIKeysParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get Api keys params
func (o *GetAPIKeysParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get Api keys params
func (o *GetAPIKeysParams) WithHTTPClient(client *http.Client) *GetAPIKeysParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get Api keys params
func (o *GetAPIKeysParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the get Api keys params
func (o *GetAPIKeysParams) WithBody(body *models.GetAPIKeysRequest) *GetAPIKeysParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the get Api keys params
func (o *GetAPIKeysParams) SetBody(body *models.GetAPIKeysRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *GetAPIKeysParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
