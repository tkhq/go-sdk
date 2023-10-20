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

// V1CreateSubOrganizationIntentV4 v1 create sub organization intent v4
//
// swagger:model v1CreateSubOrganizationIntentV4
type V1CreateSubOrganizationIntentV4 struct {

	// Disable email recovery for the sub-organization
	DisableEmailRecovery bool `json:"disableEmailRecovery,omitempty"`

	// The threshold of unique approvals to reach root quorum. This value must be less than or equal to the number of root users
	// Required: true
	RootQuorumThreshold *int32 `json:"rootQuorumThreshold"`

	// Root users to create within this sub-organization
	// Required: true
	RootUsers []*V1RootUserParams `json:"rootUsers"`

	// Name for this sub-organization
	// Required: true
	SubOrganizationName *string `json:"subOrganizationName"`

	// The wallet to create for the sub-organization
	Wallet *V1WalletParams `json:"wallet,omitempty"`
}

// Validate validates this v1 create sub organization intent v4
func (m *V1CreateSubOrganizationIntentV4) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateRootQuorumThreshold(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRootUsers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateSubOrganizationName(formats); err != nil {
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

func (m *V1CreateSubOrganizationIntentV4) validateRootQuorumThreshold(formats strfmt.Registry) error {

	if err := validate.Required("rootQuorumThreshold", "body", m.RootQuorumThreshold); err != nil {
		return err
	}

	return nil
}

func (m *V1CreateSubOrganizationIntentV4) validateRootUsers(formats strfmt.Registry) error {

	if err := validate.Required("rootUsers", "body", m.RootUsers); err != nil {
		return err
	}

	for i := 0; i < len(m.RootUsers); i++ {
		if swag.IsZero(m.RootUsers[i]) { // not required
			continue
		}

		if m.RootUsers[i] != nil {
			if err := m.RootUsers[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("rootUsers" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("rootUsers" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1CreateSubOrganizationIntentV4) validateSubOrganizationName(formats strfmt.Registry) error {

	if err := validate.Required("subOrganizationName", "body", m.SubOrganizationName); err != nil {
		return err
	}

	return nil
}

func (m *V1CreateSubOrganizationIntentV4) validateWallet(formats strfmt.Registry) error {
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

// ContextValidate validate this v1 create sub organization intent v4 based on the context it is used
func (m *V1CreateSubOrganizationIntentV4) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateRootUsers(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateWallet(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1CreateSubOrganizationIntentV4) contextValidateRootUsers(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.RootUsers); i++ {

		if m.RootUsers[i] != nil {

			if swag.IsZero(m.RootUsers[i]) { // not required
				return nil
			}

			if err := m.RootUsers[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("rootUsers" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("rootUsers" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1CreateSubOrganizationIntentV4) contextValidateWallet(ctx context.Context, formats strfmt.Registry) error {

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
func (m *V1CreateSubOrganizationIntentV4) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1CreateSubOrganizationIntentV4) UnmarshalBinary(b []byte) error {
	var res V1CreateSubOrganizationIntentV4
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
