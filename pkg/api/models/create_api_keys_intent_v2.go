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

// CreateAPIKeysIntentV2 create Api keys intent v2
//
// swagger:model CreateApiKeysIntentV2
type CreateAPIKeysIntentV2 struct {

	// A list of API Keys.
	// Required: true
	APIKeys []*APIKeyParamsV2 `json:"apiKeys"`

	// Unique identifier for a given User.
	// Required: true
	UserID *string `json:"userId"`
}

// Validate validates this create Api keys intent v2
func (m *CreateAPIKeysIntentV2) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateAPIKeys(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserID(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CreateAPIKeysIntentV2) validateAPIKeys(formats strfmt.Registry) error {

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

func (m *CreateAPIKeysIntentV2) validateUserID(formats strfmt.Registry) error {

	if err := validate.Required("userId", "body", m.UserID); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this create Api keys intent v2 based on the context it is used
func (m *CreateAPIKeysIntentV2) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateAPIKeys(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CreateAPIKeysIntentV2) contextValidateAPIKeys(ctx context.Context, formats strfmt.Registry) error {

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

// MarshalBinary interface implementation
func (m *CreateAPIKeysIntentV2) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CreateAPIKeysIntentV2) UnmarshalBinary(b []byte) error {
	var res CreateAPIKeysIntentV2
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
