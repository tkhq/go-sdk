// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// EmailCustomizationParams email customization params
//
// swagger:model EmailCustomizationParams
type EmailCustomizationParams struct {

	// The name of the application.
	AppName *string `json:"appName,omitempty"`

	// A URL pointing to a logo in PNG format. Note this logo will be resized to fit into 340px x 124px.
	LogoURL *string `json:"logoUrl,omitempty"`

	// A template for the URL to be used in a magic link button, e.g. `https://dapp.xyz/%s`. The auth bundle will be interpolated into the `%s`.
	MagicLinkTemplate *string `json:"magicLinkTemplate,omitempty"`

	// Unique identifier for a given Email Template. If not specified, the default is the most recent Email Template.
	TemplateID *string `json:"templateId,omitempty"`

	// JSON object containing key/value pairs to be used with custom templates.
	TemplateVariables *string `json:"templateVariables,omitempty"`
}

// Validate validates this email customization params
func (m *EmailCustomizationParams) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this email customization params based on context it is used
func (m *EmailCustomizationParams) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *EmailCustomizationParams) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EmailCustomizationParams) UnmarshalBinary(b []byte) error {
	var res EmailCustomizationParams
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
