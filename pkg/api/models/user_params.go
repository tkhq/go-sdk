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

// UserParams user params
//
// swagger:model UserParams
type UserParams struct {

	// The User's permissible access method(s).
	// Required: true
	AccessType *AccessType `json:"accessType"`

	// A list of API Key parameters. This field, if not needed, should be an empty array in your request body.
	// Required: true
	APIKeys []*APIKeyParams `json:"apiKeys"`

	// A list of Authenticator parameters. This field, if not needed, should be an empty array in your request body.
	// Required: true
	Authenticators []*AuthenticatorParams `json:"authenticators"`

	// The user's email address.
	UserEmail *string `json:"userEmail,omitempty"`

	// Human-readable name for a User.
	// Required: true
	UserName *string `json:"userName"`

	// A list of User Tag IDs. This field, if not needed, should be an empty array in your request body.
	// Required: true
	UserTags []string `json:"userTags"`
}

// Validate validates this user params
func (m *UserParams) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAccessType(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAPIKeys(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateAuthenticators(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserTags(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserParams) validateAccessType(formats strfmt.Registry) error {

	if err := validate.Required("accessType", "body", m.AccessType); err != nil {
		return err
	}

	if err := validate.Required("accessType", "body", m.AccessType); err != nil {
		return err
	}

	if m.AccessType != nil {
		if err := m.AccessType.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("accessType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("accessType")
			}
			return err
		}
	}

	return nil
}

func (m *UserParams) validateAPIKeys(formats strfmt.Registry) error {

	if err := validate.Required("apiKeys", "body", m.APIKeys); err != nil {
		return err
	}

	for i := 0; i < len(m.APIKeys); i++ {
		if swag.IsZero(m.APIKeys[i]) { // not required
			continue
		}

		if m.APIKeys[i] != nil {
			if err := m.APIKeys[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("apiKeys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("apiKeys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *UserParams) validateAuthenticators(formats strfmt.Registry) error {

	if err := validate.Required("authenticators", "body", m.Authenticators); err != nil {
		return err
	}

	for i := 0; i < len(m.Authenticators); i++ {
		if swag.IsZero(m.Authenticators[i]) { // not required
			continue
		}

		if m.Authenticators[i] != nil {
			if err := m.Authenticators[i].Validate(formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("authenticators" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("authenticators" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *UserParams) validateUserName(formats strfmt.Registry) error {

	if err := validate.Required("userName", "body", m.UserName); err != nil {
		return err
	}

	return nil
}

func (m *UserParams) validateUserTags(formats strfmt.Registry) error {

	if err := validate.Required("userTags", "body", m.UserTags); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this user params based on the context it is used
func (m *UserParams) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAccessType(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAPIKeys(ctx, formats); err != nil {
		res = append(res, err)
	}

	if err := m.contextValidateAuthenticators(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *UserParams) contextValidateAccessType(ctx context.Context, formats strfmt.Registry) error {

	if m.AccessType != nil {

		if err := m.AccessType.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("accessType")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("accessType")
			}
			return err
		}
	}

	return nil
}

func (m *UserParams) contextValidateAPIKeys(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.APIKeys); i++ {

		if m.APIKeys[i] != nil {

			if swag.IsZero(m.APIKeys[i]) { // not required
				return nil
			}

			if err := m.APIKeys[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("apiKeys" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("apiKeys" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

func (m *UserParams) contextValidateAuthenticators(ctx context.Context, formats strfmt.Registry) error {

	for i := 0; i < len(m.Authenticators); i++ {

		if m.Authenticators[i] != nil {

			if swag.IsZero(m.Authenticators[i]) { // not required
				return nil
			}

			if err := m.Authenticators[i].ContextValidate(ctx, formats); err != nil {
				if ve, ok := err.(*errors.Validation); ok {
					return ve.ValidateName("authenticators" + "." + strconv.Itoa(i))
				} else if ce, ok := err.(*errors.CompositeError); ok {
					return ce.ValidateName("authenticators" + "." + strconv.Itoa(i))
				}
				return err
			}
		}

	}

	return nil
}

// MarshalBinary interface implementation
func (m *UserParams) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *UserParams) UnmarshalBinary(b []byte) error {
	var res UserParams
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
