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

// V1GetWhoamiResponse v1 get whoami response
//
// swagger:model v1GetWhoamiResponse
type V1GetWhoamiResponse struct {

	// Unique identifier for a given Organization.
	// Required: true
	OrganizationID *string `json:"organizationId"`

	// Human-readable name for an Organization.
	// Required: true
	OrganizationName *string `json:"organizationName"`

	// Unique identifier for a given User.
	// Required: true
	UserID *string `json:"userId"`

	// Human-readable name for a User.
	// Required: true
	Username *string `json:"username"`
}

// Validate validates this v1 get whoami response
func (m *V1GetWhoamiResponse) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateOrganizationID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateOrganizationName(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUserID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateUsername(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1GetWhoamiResponse) validateOrganizationID(formats strfmt.Registry) error {

	if err := validate.Required("organizationId", "body", m.OrganizationID); err != nil {
		return err
	}

	return nil
}

func (m *V1GetWhoamiResponse) validateOrganizationName(formats strfmt.Registry) error {

	if err := validate.Required("organizationName", "body", m.OrganizationName); err != nil {
		return err
	}

	return nil
}

func (m *V1GetWhoamiResponse) validateUserID(formats strfmt.Registry) error {

	if err := validate.Required("userId", "body", m.UserID); err != nil {
		return err
	}

	return nil
}

func (m *V1GetWhoamiResponse) validateUsername(formats strfmt.Registry) error {

	if err := validate.Required("username", "body", m.Username); err != nil {
		return err
	}

	return nil
}

// ContextValidate validates this v1 get whoami response based on context it is used
func (m *V1GetWhoamiResponse) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *V1GetWhoamiResponse) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1GetWhoamiResponse) UnmarshalBinary(b []byte) error {
	var res V1GetWhoamiResponse
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
