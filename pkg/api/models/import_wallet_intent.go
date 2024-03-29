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

// ImportWalletIntent import wallet intent
//
// swagger:model ImportWalletIntent
type ImportWalletIntent struct {

	// A list of wallet Accounts.
	// Required: true
	Accounts []*WalletAccountParams `json:"accounts"`

	// Bundle containing a wallet mnemonic encrypted to the enclave's target public key.
	// Required: true
	EncryptedBundle *string `json:"encryptedBundle"`

	// The ID of the User importing a Wallet.
	// Required: true
	UserID *string `json:"userId"`

	// Human-readable name for a Wallet.
	// Required: true
	WalletName *string `json:"walletName"`
}

// Validate validates this import wallet intent
func (m *ImportWalletIntent) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccounts(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateEncryptedBundle(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserID(formats); err != nil {
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

func (m *ImportWalletIntent) validateAccounts(formats strfmt.Registry) error {

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

func (m *ImportWalletIntent) validateEncryptedBundle(formats strfmt.Registry) error {

	if err := validate.Required("encryptedBundle", "body", m.EncryptedBundle); err != nil {
		return err
	}

	return nil
}

func (m *ImportWalletIntent) validateUserID(formats strfmt.Registry) error {

	if err := validate.Required("userId", "body", m.UserID); err != nil {
		return err
	}

	return nil
}

func (m *ImportWalletIntent) validateWalletName(formats strfmt.Registry) error {

	if err := validate.Required("walletName", "body", m.WalletName); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this import wallet intent based on the context it is used
func (m *ImportWalletIntent) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccounts(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *ImportWalletIntent) contextValidateAccounts(ctx context.Context, formats strfmt.Registry) error {

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
func (m *ImportWalletIntent) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *ImportWalletIntent) UnmarshalBinary(b []byte) error {
	var res ImportWalletIntent
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
