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

// OauthProviderParams oauth provider params
//
// swagger:model OauthProviderParams
type OauthProviderParams struct {

	// The URL at which to fetch the OIDC token signers
	// Required: true
	JwksURI *string `json:"jwksUri"`

	// Base64 encoded OIDC token
	// Required: true
	OidcToken *string `json:"oidcToken"`

	// Human-readable name to identify a Provider.
	// Required: true
	ProviderName *string `json:"providerName"`
}

// Validate validates this oauth provider params
func (m *OauthProviderParams) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateJwksURI(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOidcToken(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateProviderName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OauthProviderParams) validateJwksURI(formats strfmt.Registry) error {

	if err := validate.Required("jwksUri", "body", m.JwksURI); err != nil {
		return err
	}

	return nil
}

func (m *OauthProviderParams) validateOidcToken(formats strfmt.Registry) error {

	if err := validate.Required("oidcToken", "body", m.OidcToken); err != nil {
		return err
	}

	return nil
}

func (m *OauthProviderParams) validateProviderName(formats strfmt.Registry) error {

	if err := validate.Required("providerName", "body", m.ProviderName); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this oauth provider params based on context it is used
func (m *OauthProviderParams) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OauthProviderParams) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OauthProviderParams) UnmarshalBinary(b []byte) error {
	var res OauthProviderParams
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
