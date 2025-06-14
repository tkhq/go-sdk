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

// VerifyOtpResult verify otp result
//
// swagger:model VerifyOtpResult
type VerifyOtpResult struct {

	// Signed JWT containing a unique id, expiry, verification type, contact. Verification status of a user is updated when the token is consumed (in OTP_LOGIN requests)
	// Required: true
	VerificationToken *string `json:"verificationToken"`
}

// Validate validates this verify otp result
func (m *VerifyOtpResult) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateVerificationToken(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *VerifyOtpResult) validateVerificationToken(formats strfmt.Registry) error {

	if err := validate.Required("verificationToken", "body", m.VerificationToken); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this verify otp result based on context it is used
func (m *VerifyOtpResult) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *VerifyOtpResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *VerifyOtpResult) UnmarshalBinary(b []byte) error {
	var res VerifyOtpResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
