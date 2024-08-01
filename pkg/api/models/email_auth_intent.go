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

// EmailAuthIntent email auth intent
//
// swagger:model EmailAuthIntent
type EmailAuthIntent struct {

	// Optional human-readable name for an API Key. If none provided, default to Email Auth - <Timestamp>
	APIKeyName string `json:"apiKeyName,omitempty"`

	// Email of the authenticating user.
	// Required: true
	Email *string `json:"email"`

	// Optional parameters for customizing emails. If not provided, the default email will be used.
	EmailCustomization *EmailCustomizationParams `json:"emailCustomization,omitempty"`

	// Expiration window (in seconds) indicating how long the API key is valid. If not provided, a default of 15 minutes will be used.
	ExpirationSeconds string `json:"expirationSeconds,omitempty"`

	// Invalidate all other previously generated Email Auth API keys
	InvalidateExisting bool `json:"invalidateExisting,omitempty"`

	// Client-side public key generated by the user, to which the email auth bundle (credentials) will be encrypted.
	// Required: true
	TargetPublicKey *string `json:"targetPublicKey"`
}

// Validate validates this email auth intent
func (m *EmailAuthIntent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateEmail(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEmailCustomization(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTargetPublicKey(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EmailAuthIntent) validateEmail(formats strfmt.Registry) error {

	if err := validate.Required("email", "body", m.Email); err != nil {
		return err
	}

	return nil
}

func (m *EmailAuthIntent) validateEmailCustomization(formats strfmt.Registry) error {
	if swag.IsZero(m.EmailCustomization) { // not required
		return nil
	}

	if m.EmailCustomization != nil {
		if err := m.EmailCustomization.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("emailCustomization")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("emailCustomization")
			}
			return err
		}
	}

	return nil
}

func (m *EmailAuthIntent) validateTargetPublicKey(formats strfmt.Registry) error {

	if err := validate.Required("targetPublicKey", "body", m.TargetPublicKey); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this email auth intent based on the context it is used
func (m *EmailAuthIntent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateEmailCustomization(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *EmailAuthIntent) contextValidateEmailCustomization(ctx context.Context, formats strfmt.Registry) error {

	if m.EmailCustomization != nil {

		if swag.IsZero(m.EmailCustomization) { // not required
			return nil
		}

		if err := m.EmailCustomization.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("emailCustomization")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("emailCustomization")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *EmailAuthIntent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *EmailAuthIntent) UnmarshalBinary(b []byte) error {
	var res EmailAuthIntent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
