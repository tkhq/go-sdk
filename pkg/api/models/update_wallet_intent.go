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

// UpdateWalletIntent update wallet intent
//
// swagger:model UpdateWalletIntent
type UpdateWalletIntent struct {

	// Unique identifier for a given Wallet.
	// Required: true
	WalletID *string `json:"walletId"`

	// Human-readable name for a Wallet.
	WalletName string `json:"walletName,omitempty"`
}

// Validate validates this update wallet intent
func (m *UpdateWalletIntent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateWalletID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UpdateWalletIntent) validateWalletID(formats strfmt.Registry) error {

	if err := validate.Required("walletId", "body", m.WalletID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this update wallet intent based on context it is used
func (m *UpdateWalletIntent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *UpdateWalletIntent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UpdateWalletIntent) UnmarshalBinary(b []byte) error {
	var res UpdateWalletIntent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
