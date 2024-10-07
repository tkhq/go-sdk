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

// OtpAuthIntent otp auth intent
//
// swagger:model OtpAuthIntent
type OtpAuthIntent struct {

	// Optional human-readable name for an API Key. If none provided, default to OTP Auth - <Timestamp>
	APIKeyName string `json:"apiKeyName,omitempty"`

	// Expiration window (in seconds) indicating how long the API key is valid. If not provided, a default of 15 minutes will be used.
	ExpirationSeconds string `json:"expirationSeconds,omitempty"`

	// Invalidate all other previously generated OTP Auth API keys
	InvalidateExisting bool `json:"invalidateExisting,omitempty"`

	// 6 digit OTP code sent out to a user's contact (email or SMS)
	// Required: true
	OtpCode *string `json:"otpCode"`

	// ID representing the result of an init OTP activity.
	// Required: true
	OtpID *string `json:"otpId"`

	// Client-side public key generated by the user, to which the OTP bundle (credentials) will be encrypted.
	TargetPublicKey string `json:"targetPublicKey,omitempty"`
}

// Validate validates this otp auth intent
func (m *OtpAuthIntent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateOtpCode(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOtpID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *OtpAuthIntent) validateOtpCode(formats strfmt.Registry) error {

	if err := validate.Required("otpCode", "body", m.OtpCode); err != nil {
		return err
	}

	return nil
}

func (m *OtpAuthIntent) validateOtpID(formats strfmt.Registry) error {

	if err := validate.Required("otpId", "body", m.OtpID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this otp auth intent based on context it is used
func (m *OtpAuthIntent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *OtpAuthIntent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *OtpAuthIntent) UnmarshalBinary(b []byte) error {
	var res OtpAuthIntent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
