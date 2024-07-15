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

// DeleteOauthProvidersIntent delete oauth providers intent
//
// swagger:model DeleteOauthProvidersIntent
type DeleteOauthProvidersIntent struct {

	// Unique identifier for a given Provider.
	// Required: true
	ProviderIds []string `json:"providerIds"`

	// The ID of the User to remove an Oauth provider from
	// Required: true
	UserID *string `json:"userId"`
}

// Validate validates this delete oauth providers intent
func (m *DeleteOauthProvidersIntent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateProviderIds(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *DeleteOauthProvidersIntent) validateProviderIds(formats strfmt.Registry) error {

	if err := validate.Required("providerIds", "body", m.ProviderIds); err != nil {
		return err
	}

	return nil
}

func (m *DeleteOauthProvidersIntent) validateUserID(formats strfmt.Registry) error {

	if err := validate.Required("userId", "body", m.UserID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this delete oauth providers intent based on context it is used
func (m *DeleteOauthProvidersIntent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *DeleteOauthProvidersIntent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *DeleteOauthProvidersIntent) UnmarshalBinary(b []byte) error {
	var res DeleteOauthProvidersIntent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}