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

// SetPaymentMethodResult set payment method result
//
// swagger:model SetPaymentMethodResult
type SetPaymentMethodResult struct {

	// The email address associated with the payment method.
	// Required: true
	CardHolderEmail *string `json:"cardHolderEmail"`

	// The name associated with the payment method.
	// Required: true
	CardHolderName *string `json:"cardHolderName"`

	// The last four digits of the credit card added.
	// Required: true
	LastFour *string `json:"lastFour"`
}

// Validate validates this set payment method result
func (m *SetPaymentMethodResult) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateCardHolderEmail(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCardHolderName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateLastFour(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SetPaymentMethodResult) validateCardHolderEmail(formats strfmt.Registry) error {

	if err := validate.Required("cardHolderEmail", "body", m.CardHolderEmail); err != nil {
		return err
	}

	return nil
}

func (m *SetPaymentMethodResult) validateCardHolderName(formats strfmt.Registry) error {

	if err := validate.Required("cardHolderName", "body", m.CardHolderName); err != nil {
		return err
	}

	return nil
}

func (m *SetPaymentMethodResult) validateLastFour(formats strfmt.Registry) error {

	if err := validate.Required("lastFour", "body", m.LastFour); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this set payment method result based on context it is used
func (m *SetPaymentMethodResult) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *SetPaymentMethodResult) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SetPaymentMethodResult) UnmarshalBinary(b []byte) error {
	var res SetPaymentMethodResult
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
