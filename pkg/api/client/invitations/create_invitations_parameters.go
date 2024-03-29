// Code generated by go-swagger; DO NOT EDIT.

package invitations

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

// NewCreateInvitationsParams creates a new CreateInvitationsParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewCreateInvitationsParams() *CreateInvitationsParams {
	return &CreateInvitationsParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewCreateInvitationsParamsWithTimeout creates a new CreateInvitationsParams object
// with the ability to set a timeout on a request.
func NewCreateInvitationsParamsWithTimeout(timeout time.Duration) *CreateInvitationsParams {
	return &CreateInvitationsParams{
		timeout: timeout,
	}
}

// NewCreateInvitationsParamsWithContext creates a new CreateInvitationsParams object
// with the ability to set a context for a request.
func NewCreateInvitationsParamsWithContext(ctx context.Context) *CreateInvitationsParams {
	return &CreateInvitationsParams{
		Context: ctx,
	}
}

// NewCreateInvitationsParamsWithHTTPClient creates a new CreateInvitationsParams object
// with the ability to set a custom HTTPClient for a request.
func NewCreateInvitationsParamsWithHTTPClient(client *http.Client) *CreateInvitationsParams {
	return &CreateInvitationsParams{
		HTTPClient: client,
	}
}

/*
CreateInvitationsParams contains all the parameters to send to the API endpoint

	for the create invitations operation.

	Typically these are written to a http.Request.
*/
type CreateInvitationsParams struct {

	// Body.
	Body *models.CreateInvitationsRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the create invitations params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateInvitationsParams) WithDefaults() *CreateInvitationsParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the create invitations params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *CreateInvitationsParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the create invitations params
func (o *CreateInvitationsParams) WithTimeout(timeout time.Duration) *CreateInvitationsParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the create invitations params
func (o *CreateInvitationsParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the create invitations params
func (o *CreateInvitationsParams) WithContext(ctx context.Context) *CreateInvitationsParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the create invitations params
func (o *CreateInvitationsParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the create invitations params
func (o *CreateInvitationsParams) WithHTTPClient(client *http.Client) *CreateInvitationsParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the create invitations params
func (o *CreateInvitationsParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the create invitations params
func (o *CreateInvitationsParams) WithBody(body *models.CreateInvitationsRequest) *CreateInvitationsParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the create invitations params
func (o *CreateInvitationsParams) SetBody(body *models.CreateInvitationsRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *CreateInvitationsParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
