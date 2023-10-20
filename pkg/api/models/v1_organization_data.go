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
)

// V1OrganizationData v1 organization data
//
// swagger:model v1OrganizationData
type V1OrganizationData struct {

	// allowed origins
	AllowedOrigins []string `json:"allowedOrigins"`

	// disabled private keys
	DisabledPrivateKeys []*V1PrivateKey `json:"disabledPrivateKeys"`

	// features
	Features []*V1Feature `json:"features"`

	// invitations
	Invitations []*V1Invitation `json:"invitations"`

	// name
	Name string `json:"name,omitempty"`

	// organization Id
	OrganizationID string `json:"organizationId,omitempty"`

	// policies
	Policies []*V1Policy `json:"policies"`

	// private keys
	PrivateKeys []*V1PrivateKey `json:"privateKeys"`

	// root quorum
	RootQuorum *Externaldatav1Quorum `json:"rootQuorum,omitempty"`

	// tags
	Tags []*Datav1Tag `json:"tags"`

	// users
	Users []*V1User `json:"users"`

	// wallets
	Wallets []*V1Wallet `json:"wallets"`
}

// Validate validates this v1 organization data
func (m *V1OrganizationData) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateDisabledPrivateKeys(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateFeatures(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateInvitations(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePolicies(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validatePrivateKeys(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateRootQuorum(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTags(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUsers(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateWallets(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1OrganizationData) validateDisabledPrivateKeys(formats strfmt.Registry) error {
	if swag.IsZero(m.DisabledPrivateKeys) { // not required
		return nil
	}

	for i := 0; i < len(m.DisabledPrivateKeys); i++ {
		if swag.IsZero(m.DisabledPrivateKeys[i]) { // not required
			continue
		}

		if m.DisabledPrivateKeys[i] != nil {
			if err := m.DisabledPrivateKeys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("disabledPrivateKeys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("disabledPrivateKeys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) validateFeatures(formats strfmt.Registry) error {
	if swag.IsZero(m.Features) { // not required
		return nil
	}

	for i := 0; i < len(m.Features); i++ {
		if swag.IsZero(m.Features[i]) { // not required
			continue
		}

		if m.Features[i] != nil {
			if err := m.Features[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("features" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("features" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) validateInvitations(formats strfmt.Registry) error {
	if swag.IsZero(m.Invitations) { // not required
		return nil
	}

	for i := 0; i < len(m.Invitations); i++ {
		if swag.IsZero(m.Invitations[i]) { // not required
			continue
		}

		if m.Invitations[i] != nil {
			if err := m.Invitations[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("invitations" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("invitations" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) validatePolicies(formats strfmt.Registry) error {
	if swag.IsZero(m.Policies) { // not required
		return nil
	}

	for i := 0; i < len(m.Policies); i++ {
		if swag.IsZero(m.Policies[i]) { // not required
			continue
		}

		if m.Policies[i] != nil {
			if err := m.Policies[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("policies" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) validatePrivateKeys(formats strfmt.Registry) error {
	if swag.IsZero(m.PrivateKeys) { // not required
		return nil
	}

	for i := 0; i < len(m.PrivateKeys); i++ {
		if swag.IsZero(m.PrivateKeys[i]) { // not required
			continue
		}

		if m.PrivateKeys[i] != nil {
			if err := m.PrivateKeys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("privateKeys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("privateKeys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) validateRootQuorum(formats strfmt.Registry) error {
	if swag.IsZero(m.RootQuorum) { // not required
		return nil
	}

	if m.RootQuorum != nil {
		if err := m.RootQuorum.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("rootQuorum")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("rootQuorum")
			}
			return err
		}
	}

	return nil
}

func (m *V1OrganizationData) validateTags(formats strfmt.Registry) error {
	if swag.IsZero(m.Tags) { // not required
		return nil
	}

	for i := 0; i < len(m.Tags); i++ {
		if swag.IsZero(m.Tags[i]) { // not required
			continue
		}

		if m.Tags[i] != nil {
			if err := m.Tags[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("tags" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("tags" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) validateUsers(formats strfmt.Registry) error {
	if swag.IsZero(m.Users) { // not required
		return nil
	}

	for i := 0; i < len(m.Users); i++ {
		if swag.IsZero(m.Users[i]) { // not required
			continue
		}

		if m.Users[i] != nil {
			if err := m.Users[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("users" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("users" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) validateWallets(formats strfmt.Registry) error {
	if swag.IsZero(m.Wallets) { // not required
		return nil
	}

	for i := 0; i < len(m.Wallets); i++ {
		if swag.IsZero(m.Wallets[i]) { // not required
			continue
		}

		if m.Wallets[i] != nil {
			if err := m.Wallets[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("wallets" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("wallets" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// ContextValidate validate this v1 organization data based on the context it is used
func (m *V1OrganizationData) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateDisabledPrivateKeys(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateFeatures(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateInvitations(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePolicies(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidatePrivateKeys(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateRootQuorum(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateTags(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateUsers(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateWallets(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1OrganizationData) contextValidateDisabledPrivateKeys(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.DisabledPrivateKeys); i++ {

		if m.DisabledPrivateKeys[i] != nil {

			if swag.IsZero(m.DisabledPrivateKeys[i]) { // not required
				return nil
			}

			if err := m.DisabledPrivateKeys[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("disabledPrivateKeys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("disabledPrivateKeys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) contextValidateFeatures(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Features); i++ {

		if m.Features[i] != nil {

			if swag.IsZero(m.Features[i]) { // not required
				return nil
			}

			if err := m.Features[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("features" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("features" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) contextValidateInvitations(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Invitations); i++ {

		if m.Invitations[i] != nil {

			if swag.IsZero(m.Invitations[i]) { // not required
				return nil
			}

			if err := m.Invitations[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("invitations" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("invitations" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) contextValidatePolicies(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Policies); i++ {

		if m.Policies[i] != nil {

			if swag.IsZero(m.Policies[i]) { // not required
				return nil
			}

			if err := m.Policies[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("policies" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("policies" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) contextValidatePrivateKeys(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.PrivateKeys); i++ {

		if m.PrivateKeys[i] != nil {

			if swag.IsZero(m.PrivateKeys[i]) { // not required
				return nil
			}

			if err := m.PrivateKeys[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("privateKeys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("privateKeys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) contextValidateRootQuorum(ctx context.Context, formats strfmt.Registry) error {

	if m.RootQuorum != nil {

		if swag.IsZero(m.RootQuorum) { // not required
			return nil
		}

		if err := m.RootQuorum.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("rootQuorum")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("rootQuorum")
			}
			return err
		}
	}

	return nil
}

func (m *V1OrganizationData) contextValidateTags(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Tags); i++ {

		if m.Tags[i] != nil {

			if swag.IsZero(m.Tags[i]) { // not required
				return nil
			}

			if err := m.Tags[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("tags" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("tags" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) contextValidateUsers(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Users); i++ {

		if m.Users[i] != nil {

			if swag.IsZero(m.Users[i]) { // not required
				return nil
			}

			if err := m.Users[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("users" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("users" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *V1OrganizationData) contextValidateWallets(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Wallets); i++ {

		if m.Wallets[i] != nil {

			if swag.IsZero(m.Wallets[i]) { // not required
				return nil
			}

			if err := m.Wallets[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("wallets" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("wallets" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1OrganizationData) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1OrganizationData) UnmarshalBinary(b []byte) error {
	var res V1OrganizationData
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
