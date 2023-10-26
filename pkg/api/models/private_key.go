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

// PrivateKey private key
//
// swagger:model PrivateKey
type PrivateKey struct {

	// Derived cryptocurrency addresses for a given Private Key.
	// Required: true
	Addresses []*DataV1Address `json:"addresses"`

	// created at
	// Required: true
	CreatedAt *ExternalDataV1Timestamp `json:"createdAt"`

	// Cryptographic Curve used to generate a given Private Key.
	// Required: true
	Curve *DataV1Curve `json:"curve"`

	// True when a given Private Key is exported, false otherwise.
	// Required: true
	Exported *bool `json:"exported"`

	// Unique identifier for a given Private Key.
	// Required: true
	PrivateKeyID *string `json:"privateKeyId"`

	// Human-readable name for a Private Key.
	// Required: true
	PrivateKeyName *string `json:"privateKeyName"`

	// A list of Private Key Tag IDs.
	// Required: true
	PrivateKeyTags []string `json:"privateKeyTags"`

	// The public component of a cryptographic key pair used to sign messages and transactions.
	// Required: true
	PublicKey *string `json:"publicKey"`

	// updated at
	// Required: true
	UpdatedAt *ExternalDataV1Timestamp `json:"updatedAt"`
}

// Validate validates this private key
func (m *PrivateKey) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAddresses(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCreatedAt(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateCurve(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateExported(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrivateKeyID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrivateKeyName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrivateKeyTags(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePublicKey(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUpdatedAt(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PrivateKey) validateAddresses(formats strfmt.Registry) error {

	if err := validate.Required("addresses", "body", m.Addresses); err != nil {
		return err
	}

	for i := 0; i < len(m.Addresses); i++ {
		if swag.IsZero(m.Addresses[i]) { // not required
			continue
		}

		if m.Addresses[i] != nil {
			if err := m.Addresses[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("addresses" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("addresses" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *PrivateKey) validateCreatedAt(formats strfmt.Registry) error {

	if err := validate.Required("createdAt", "body", m.CreatedAt); err != nil {
		return err
	}

	if m.CreatedAt != nil {
		if err := m.CreatedAt.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("createdAt")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("createdAt")
			}
			return err
		}
	}

	return nil
}

func (m *PrivateKey) validateCurve(formats strfmt.Registry) error {

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

func (m *PrivateKey) validateExported(formats strfmt.Registry) error {

	if err := validate.Required("exported", "body", m.Exported); err != nil {
		return err
	}

	return nil
}

func (m *PrivateKey) validatePrivateKeyID(formats strfmt.Registry) error {

	if err := validate.Required("privateKeyId", "body", m.PrivateKeyID); err != nil {
		return err
	}

	return nil
}

func (m *PrivateKey) validatePrivateKeyName(formats strfmt.Registry) error {

	if err := validate.Required("privateKeyName", "body", m.PrivateKeyName); err != nil {
		return err
	}

	return nil
}

func (m *PrivateKey) validatePrivateKeyTags(formats strfmt.Registry) error {

	if err := validate.Required("privateKeyTags", "body", m.PrivateKeyTags); err != nil {
		return err
	}

	return nil
}

func (m *PrivateKey) validatePublicKey(formats strfmt.Registry) error {

	if err := validate.Required("publicKey", "body", m.PublicKey); err != nil {
		return err
	}

	return nil
}

func (m *PrivateKey) validateUpdatedAt(formats strfmt.Registry) error {

	if err := validate.Required("updatedAt", "body", m.UpdatedAt); err != nil {
		return err
	}

	if m.UpdatedAt != nil {
		if err := m.UpdatedAt.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("updatedAt")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("updatedAt")
			}
			return err
		}
	}

	return nil
}

// ContextValidate validate this private key based on the context it is used
func (m *PrivateKey) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAddresses(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCreatedAt(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateCurve(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateUpdatedAt(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *PrivateKey) contextValidateAddresses(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Addresses); i++ {

		if m.Addresses[i] != nil {
			if err := m.Addresses[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("addresses" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("addresses" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *PrivateKey) contextValidateCreatedAt(ctx context.Context, formats strfmt.Registry) error {

	if m.CreatedAt != nil {
		if err := m.CreatedAt.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("createdAt")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("createdAt")
			}
			return err
		}
	}

	return nil
}

func (m *PrivateKey) contextValidateCurve(ctx context.Context, formats strfmt.Registry) error {

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

func (m *PrivateKey) contextValidateUpdatedAt(ctx context.Context, formats strfmt.Registry) error {

	if m.UpdatedAt != nil {
		if err := m.UpdatedAt.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("updatedAt")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("updatedAt")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *PrivateKey) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *PrivateKey) UnmarshalBinary(b []byte) error {
	var res PrivateKey
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
