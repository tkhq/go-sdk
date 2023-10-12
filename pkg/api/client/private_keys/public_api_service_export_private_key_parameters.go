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

// NewPublicAPIServiceExportPrivateKeyParams creates a new PublicAPIServiceExportPrivateKeyParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewPublicAPIServiceExportPrivateKeyParams() *PublicAPIServiceExportPrivateKeyParams {
	return &PublicAPIServiceExportPrivateKeyParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewPublicAPIServiceExportPrivateKeyParamsWithTimeout creates a new PublicAPIServiceExportPrivateKeyParams object
// with the ability to set a timeout on a request.
func NewPublicAPIServiceExportPrivateKeyParamsWithTimeout(timeout time.Duration) *PublicAPIServiceExportPrivateKeyParams {
	return &PublicAPIServiceExportPrivateKeyParams{
		timeout: timeout,
	}
}

// NewPublicAPIServiceExportPrivateKeyParamsWithContext creates a new PublicAPIServiceExportPrivateKeyParams object
// with the ability to set a context for a request.
func NewPublicAPIServiceExportPrivateKeyParamsWithContext(ctx context.Context) *PublicAPIServiceExportPrivateKeyParams {
	return &PublicAPIServiceExportPrivateKeyParams{
		Context: ctx,
	}
}

// NewPublicAPIServiceExportPrivateKeyParamsWithHTTPClient creates a new PublicAPIServiceExportPrivateKeyParams object
// with the ability to set a custom HTTPClient for a request.
func NewPublicAPIServiceExportPrivateKeyParamsWithHTTPClient(client *http.Client) *PublicAPIServiceExportPrivateKeyParams {
	return &PublicAPIServiceExportPrivateKeyParams{
		HTTPClient: client,
	}
}

/*
PublicAPIServiceExportPrivateKeyParams contains all the parameters to send to the API endpoint

	for the public Api service export private key operation.

	Typically these are written to a http.Request.
*/
type PublicAPIServiceExportPrivateKeyParams struct {

	// Body.
	Body *models.V1ExportPrivateKeyRequest

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the public Api service export private key params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PublicAPIServiceExportPrivateKeyParams) WithDefaults() *PublicAPIServiceExportPrivateKeyParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the public Api service export private key params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *PublicAPIServiceExportPrivateKeyParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the public Api service export private key params
func (o *PublicAPIServiceExportPrivateKeyParams) WithTimeout(timeout time.Duration) *PublicAPIServiceExportPrivateKeyParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the public Api service export private key params
func (o *PublicAPIServiceExportPrivateKeyParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the public Api service export private key params
func (o *PublicAPIServiceExportPrivateKeyParams) WithContext(ctx context.Context) *PublicAPIServiceExportPrivateKeyParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the public Api service export private key params
func (o *PublicAPIServiceExportPrivateKeyParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the public Api service export private key params
func (o *PublicAPIServiceExportPrivateKeyParams) WithHTTPClient(client *http.Client) *PublicAPIServiceExportPrivateKeyParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the public Api service export private key params
func (o *PublicAPIServiceExportPrivateKeyParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithBody adds the body to the public Api service export private key params
func (o *PublicAPIServiceExportPrivateKeyParams) WithBody(body *models.V1ExportPrivateKeyRequest) *PublicAPIServiceExportPrivateKeyParams {
	o.SetBody(body)
	return o
}

// SetBody adds the body to the public Api service export private key params
func (o *PublicAPIServiceExportPrivateKeyParams) SetBody(body *models.V1ExportPrivateKeyRequest) {
	o.Body = body
}

// WriteToRequest writes these params to a swagger request
func (o *PublicAPIServiceExportPrivateKeyParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

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
