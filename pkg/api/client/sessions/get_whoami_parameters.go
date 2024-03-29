// Code generated by go-swagger; DO NOT EDIT.

package sessions

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

// NewGetWhoamiParams creates a new GetWhoamiParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewGetWhoamiParams() *GetWhoamiParams {
	return &GetWhoamiParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewGetWhoamiParamsWithTimeout creates a new GetWhoamiParams object
// with the ability to set a timeout on a request.
func NewGetWhoamiParamsWithTimeout(timeout time.Duration) *GetWhoamiParams {
	return &GetWhoamiParams{
		timeout: timeout,
	}
}

// NewGetWhoamiParamsWithContext creates a new GetWhoamiParams object
// with the ability to set a context for a request.
func NewGetWhoamiParamsWithContext(ctx context.Context) *GetWhoamiParams {
	return &GetWhoamiParams{
		Context: ctx,
	}
}

// NewGetWhoamiParamsWithHTTPClient creates a new GetWhoamiParams object
// with the ability to set a custom HTTPClient for a request.
func NewGetWhoamiParamsWithHTTPClient(client *http.Client) *GetWhoamiParams {
	return &GetWhoamiParams{
		HTTPClient: client,
	}
}

/*
GetWhoamiParams contains all the parameters to send to the API endpoint

	for the get whoami operation.

	Typically these are written to a http.Request.
*/
type GetWhoamiParams struct {

	// Body.
	Body *models.GetWhoamiRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the get whoami params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetWhoamiParams) WithDefaults() *GetWhoamiParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the get whoami params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *GetWhoamiParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the get whoami params
func (o *GetWhoamiParams) WithTimeout(timeout time.Duration) *GetWhoamiParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the get whoami params
func (o *GetWhoamiParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the get whoami params
func (o *GetWhoamiParams) WithContext(ctx context.Context) *GetWhoamiParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the get whoami params
func (o *GetWhoamiParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the get whoami params
func (o *GetWhoamiParams) WithHTTPClient(client *http.Client) *GetWhoamiParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the get whoami params
func (o *GetWhoamiParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the get whoami params
func (o *GetWhoamiParams) WithBody(body *models.GetWhoamiRequest) *GetWhoamiParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the get whoami params
func (o *GetWhoamiParams) SetBody(body *models.GetWhoamiRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *GetWhoamiParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
