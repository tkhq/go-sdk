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

// CreateSubOrganizationResultV4 create sub organization result v4
//
// swagger:model CreateSubOrganizationResultV4
type CreateSubOrganizationResultV4 struct {

	// sub organization Id
	// Required: true
	SubOrganizationID *string `json:"subOrganizationId"`

	// wallet
	Wallet *WalletResult `json:"wallet,omitempty"`
}

// Validate validates this create sub organization result v4
func (m *CreateSubOrganizationResultV4) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateSubOrganizationID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWallet(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CreateSubOrganizationResultV4) validateSubOrganizationID(formats strfmt.Registry) error {

	if err := validate.Required("subOrganizationId", "body", m.SubOrganizationID); err != nil {
		return err
	}

	return nil
}

func (m *CreateSubOrganizationResultV4) validateWallet(formats strfmt.Registry) error {
	if swag.IsZero(m.Wallet) { // not required
		return nil
	}

	if m.Wallet != nil {
		if err := m.Wallet.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("wallet")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("wallet")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this create sub organization result v4 based on the context it is used
func (m *CreateSubOrganizationResultV4) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateWallet(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CreateSubOrganizationResultV4) contextValidateWallet(ctx context.Context, formats strfmt.Registry) error {

	if m.Wallet != nil {

		if swag.IsZero(m.Wallet) { // not required
			return nil
		}

		if err := m.Wallet.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("wallet")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("wallet")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *CreateSubOrganizationResultV4) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CreateSubOrganizationResultV4) UnmarshalBinary(b []byte) error {
	var res CreateSubOrganizationResultV4
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
