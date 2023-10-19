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

// V1WalletAccountParams v1 wallet account params
//
// swagger:model v1WalletAccountParams
type V1WalletAccountParams struct {

	// Address format used to generate a wallet Acccount.
	// Required: true
	AddressFormat *Immutablecommonv1AddressFormat `json:"addressFormat"`

	// Cryptographic curve used to generate a wallet Account.
	// Required: true
	Curve *Immutablecommonv1Curve `json:"curve"`

	// Path used to generate a wallet Account.
	// Required: true
	Path *string `json:"path"`

	// Path format used to generate a wallet Account.
	// Required: true
	PathFormat *V1PathFormat `json:"pathFormat"`
}

// Validate validates this v1 wallet account params
func (m *V1WalletAccountParams) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddressFormat(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCurve(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePath(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePathFormat(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1WalletAccountParams) validateAddressFormat(formats strfmt.Registry) error {

	if err := validate.Required("addressFormat", "body", m.AddressFormat); err != nil {
		return err
	}

	if err := validate.Required("addressFormat", "body", m.AddressFormat); err != nil {
		return err
	}

	if m.AddressFormat != nil {
		if err := m.AddressFormat.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("addressFormat")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("addressFormat")
			}
			return err
		}
	}

	return nil
}

func (m *V1WalletAccountParams) validateCurve(formats strfmt.Registry) error {

	if err := validate.Required("curve", "body", m.Curve); err != nil {
		return err
	}

	if err := validate.Required("curve", "body", m.Curve); err != nil {
		return err
	}

	if m.Curve != nil {
		if err := m.Curve.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("curve")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("curve")
			}
			return err
		}
	}

	return nil
}

func (m *V1WalletAccountParams) validatePath(formats strfmt.Registry) error {

	if err := validate.Required("path", "body", m.Path); err != nil {
		return err
	}

	return nil
}

func (m *V1WalletAccountParams) validatePathFormat(formats strfmt.Registry) error {

	if err := validate.Required("pathFormat", "body", m.PathFormat); err != nil {
		return err
	}

	if err := validate.Required("pathFormat", "body", m.PathFormat); err != nil {
		return err
	}

	if m.PathFormat != nil {
		if err := m.PathFormat.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pathFormat")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pathFormat")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this v1 wallet account params based on the context it is used
func (m *V1WalletAccountParams) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAddressFormat(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCurve(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePathFormat(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1WalletAccountParams) contextValidateAddressFormat(ctx context.Context, formats strfmt.Registry) error {

	if m.AddressFormat != nil {

		if err := m.AddressFormat.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("addressFormat")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("addressFormat")
			}
			return err
		}
	}

	return nil
}

func (m *V1WalletAccountParams) contextValidateCurve(ctx context.Context, formats strfmt.Registry) error {

	if m.Curve != nil {

		if err := m.Curve.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("curve")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("curve")
			}
			return err
		}
	}

	return nil
}

func (m *V1WalletAccountParams) contextValidatePathFormat(ctx context.Context, formats strfmt.Registry) error {

	if m.PathFormat != nil {

		if err := m.PathFormat.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("pathFormat")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("pathFormat")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1WalletAccountParams) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1WalletAccountParams) UnmarshalBinary(b []byte) error {
	var res V1WalletAccountParams
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}