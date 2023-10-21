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

// NewCreateSubOrganizationParams creates a new CreateSubOrganizationParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateSubOrganizationParams() *CreateSubOrganizationParams {
	return &CreateSubOrganizationParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateSubOrganizationParamsWithTimeout creates a new CreateSubOrganizationParams object
// with the ability to set a timeout on a request.
func NewCreateSubOrganizationParamsWithTimeout(timeout time.Duration) *CreateSubOrganizationParams {
	return &CreateSubOrganizationParams{
		timeout: timeout,
	}
}

// NewCreateSubOrganizationParamsWithContext creates a new CreateSubOrganizationParams object
// with the ability to set a context for a request.
func NewCreateSubOrganizationParamsWithContext(ctx context.Context) *CreateSubOrganizationParams {
	return &CreateSubOrganizationParams{
		Context: ctx,
	}
}

// NewCreateSubOrganizationParamsWithHTTPClient creates a new CreateSubOrganizationParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateSubOrganizationParamsWithHTTPClient(client *http.Client) *CreateSubOrganizationParams {
	return &CreateSubOrganizationParams{
		HTTPClient: client,
	}
}

/*
CreateSubOrganizationParams contains all the parameters to send to the API endpoint

	for the create sub organization operation.

	Typically these are written to a http.Request.
*/
type CreateSubOrganizationParams struct {

	// Body.
	Body *models.CreateSubOrganizationRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create sub organization params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateSubOrganizationParams) WithDefaults() *CreateSubOrganizationParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create sub organization params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateSubOrganizationParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create sub organization params
func (o *CreateSubOrganizationParams) WithTimeout(timeout time.Duration) *CreateSubOrganizationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create sub organization params
func (o *CreateSubOrganizationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create sub organization params
func (o *CreateSubOrganizationParams) WithContext(ctx context.Context) *CreateSubOrganizationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create sub organization params
func (o *CreateSubOrganizationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create sub organization params
func (o *CreateSubOrganizationParams) WithHTTPClient(client *http.Client) *CreateSubOrganizationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create sub organization params
func (o *CreateSubOrganizationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the create sub organization params
func (o *CreateSubOrganizationParams) WithBody(body *models.CreateSubOrganizationRequest) *CreateSubOrganizationParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the create sub organization params
func (o *CreateSubOrganizationParams) SetBody(body *models.CreateSubOrganizationRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *CreateSubOrganizationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
