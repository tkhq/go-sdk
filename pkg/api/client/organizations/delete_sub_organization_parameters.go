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

// NewDeleteSubOrganizationParams creates a new DeleteSubOrganizationParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewDeleteSubOrganizationParams() *DeleteSubOrganizationParams {
	return &DeleteSubOrganizationParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewDeleteSubOrganizationParamsWithTimeout creates a new DeleteSubOrganizationParams object
// with the ability to set a timeout on a request.
func NewDeleteSubOrganizationParamsWithTimeout(timeout time.Duration) *DeleteSubOrganizationParams {
	return &DeleteSubOrganizationParams{
		timeout: timeout,
	}
}

// NewDeleteSubOrganizationParamsWithContext creates a new DeleteSubOrganizationParams object
// with the ability to set a context for a request.
func NewDeleteSubOrganizationParamsWithContext(ctx context.Context) *DeleteSubOrganizationParams {
	return &DeleteSubOrganizationParams{
		Context: ctx,
	}
}

// NewDeleteSubOrganizationParamsWithHTTPClient creates a new DeleteSubOrganizationParams object
// with the ability to set a custom HTTPClient for a request.
func NewDeleteSubOrganizationParamsWithHTTPClient(client *http.Client) *DeleteSubOrganizationParams {
	return &DeleteSubOrganizationParams{
		HTTPClient: client,
	}
}

/*
DeleteSubOrganizationParams contains all the parameters to send to the API endpoint

	for the delete sub organization operation.

	Typically these are written to a http.Request.
*/
type DeleteSubOrganizationParams struct {

	// Body.
	Body *models.DeleteSubOrganizationRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the delete sub organization params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteSubOrganizationParams) WithDefaults() *DeleteSubOrganizationParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the delete sub organization params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *DeleteSubOrganizationParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the delete sub organization params
func (o *DeleteSubOrganizationParams) WithTimeout(timeout time.Duration) *DeleteSubOrganizationParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the delete sub organization params
func (o *DeleteSubOrganizationParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the delete sub organization params
func (o *DeleteSubOrganizationParams) WithContext(ctx context.Context) *DeleteSubOrganizationParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the delete sub organization params
func (o *DeleteSubOrganizationParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the delete sub organization params
func (o *DeleteSubOrganizationParams) WithHTTPClient(client *http.Client) *DeleteSubOrganizationParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the delete sub organization params
func (o *DeleteSubOrganizationParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the delete sub organization params
func (o *DeleteSubOrganizationParams) WithBody(body *models.DeleteSubOrganizationRequest) *DeleteSubOrganizationParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the delete sub organization params
func (o *DeleteSubOrganizationParams) SetBody(body *models.DeleteSubOrganizationRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *DeleteSubOrganizationParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
