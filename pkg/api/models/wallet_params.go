// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"strconv"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// WalletParams wallet params
//
// swagger:model WalletParams
type WalletParams struct {

	// A list of wallet Accounts.
	// Required: true
	Accounts []*WalletAccountParams `json:"accounts"`

	// Length of mnemonic to generate the Wallet seed. Defaults to 12. Accepted values: 12, 15, 18, 21, 24.
	MnemonicLength int32 `json:"mnemonicLength,omitempty"`

	// Human-readable name for a Wallet.
	// Required: true
	WalletName *string `json:"walletName"`
}

// Validate validates this wallet params
func (m *WalletParams) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccounts(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWalletName(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *WalletParams) validateAccounts(formats strfmt.Registry) error {

	if err := validate.Required("accounts", "body", m.Accounts); err != nil {
		return err
	}

	for i := 0; i < len(m.Accounts); i++ {
		if swag.IsZero(m.Accounts[i]) { // not required
			continue
		}

		if m.Accounts[i] != nil {
			if err := m.Accounts[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("accounts" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("accounts" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *WalletParams) validateWalletName(formats strfmt.Registry) error {

	if err := validate.Required("walletName", "body", m.WalletName); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this wallet params based on the context it is used
func (m *WalletParams) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccounts(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *WalletParams) contextValidateAccounts(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Accounts); i++ {

		if m.Accounts[i] != nil {

			if swag.IsZero(m.Accounts[i]) { // not required
				return nil
			}

			if err := m.Accounts[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("accounts" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("accounts" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *WalletParams) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *WalletParams) UnmarshalBinary(b []byte) error {
	var res WalletParams
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
