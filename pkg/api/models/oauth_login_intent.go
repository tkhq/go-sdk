// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// OauthLoginIntent oauth login intent
//
// swagger:model OauthLoginIntent
type OauthLoginIntent struct {

	// Expiration window (in seconds) indicating how long the Session is valid for. If not provided, a default of 15 minutes will be used.
	ExpirationSeconds *string `json:"expirationSeconds,omitempty"`

	// Invalidate all other previously generated Login API keys
	InvalidateExisting *bool `json:"invalidateExisting,omitempty"`

	// Base64 encoded OIDC token
	// Required: true
	OidcToken *string `json:"oidcToken"`

	// Client-side public key generated by the user, which will be conditionally added to org data based on the validity of the oidc token associated with this request
	// Required: true
	PublicKey *string `json:"publicKey"`
}

// Validate validates this oauth login intent
func (m *OauthLoginIntent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateOidcToken(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePublicKey(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OauthLoginIntent) validateOidcToken(formats strfmt.Registry) error {

	if err := validate.Required("oidcToken", "body", m.OidcToken); err != nil {
		return err
	}

	return nil
}

func (m *OauthLoginIntent) validatePublicKey(formats strfmt.Registry) error {

	if err := validate.Required("publicKey", "body", m.PublicKey); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this oauth login intent based on context it is used
func (m *OauthLoginIntent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OauthLoginIntent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OauthLoginIntent) UnmarshalBinary(b []byte) error {
	var res OauthLoginIntent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
