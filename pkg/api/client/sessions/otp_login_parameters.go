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

// NewOtpLoginParams creates a new OtpLoginParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewOtpLoginParams() *OtpLoginParams {
	return &OtpLoginParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewOtpLoginParamsWithTimeout creates a new OtpLoginParams object
// with the ability to set a timeout on a request.
func NewOtpLoginParamsWithTimeout(timeout time.Duration) *OtpLoginParams {
	return &OtpLoginParams{
		timeout: timeout,
	}
}

// NewOtpLoginParamsWithContext creates a new OtpLoginParams object
// with the ability to set a context for a request.
func NewOtpLoginParamsWithContext(ctx context.Context) *OtpLoginParams {
	return &OtpLoginParams{
		Context: ctx,
	}
}

// NewOtpLoginParamsWithHTTPClient creates a new OtpLoginParams object
// with the ability to set a custom HTTPClient for a request.
func NewOtpLoginParamsWithHTTPClient(client *http.Client) *OtpLoginParams {
	return &OtpLoginParams{
		HTTPClient: client,
	}
}

/*
OtpLoginParams contains all the parameters to send to the API endpoint

	for the otp login operation.

	Typically these are written to a http.Request.
*/
type OtpLoginParams struct {

	// Body.
	Body *models.OtpLoginRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the otp login params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OtpLoginParams) WithDefaults() *OtpLoginParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the otp login params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OtpLoginParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the otp login params
func (o *OtpLoginParams) WithTimeout(timeout time.Duration) *OtpLoginParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the otp login params
func (o *OtpLoginParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the otp login params
func (o *OtpLoginParams) WithContext(ctx context.Context) *OtpLoginParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the otp login params
func (o *OtpLoginParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the otp login params
func (o *OtpLoginParams) WithHTTPClient(client *http.Client) *OtpLoginParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the otp login params
func (o *OtpLoginParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the otp login params
func (o *OtpLoginParams) WithBody(body *models.OtpLoginRequest) *OtpLoginParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the otp login params
func (o *OtpLoginParams) SetBody(body *models.OtpLoginRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *OtpLoginParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
