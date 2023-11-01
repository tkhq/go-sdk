// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

// SetOrganizationFeatureRequest set organization feature request
//
// swagger:model SetOrganizationFeatureRequest
type SetOrganizationFeatureRequest struct {

	// Unique identifier for a given Organization.
	// Required: true
	OrganizationID *string `json:"organizationId"`

	// parameters
	// Required: true
	Parameters *SetOrganizationFeatureIntent `json:"parameters"`

	// Timestamp (in milliseconds) of the request, used to verify liveness of user requests.
	// Required: true
	TimestampMs *string `json:"timestampMs"`

	// type
	// Required: true
	// Enum: [ACTIVITY_TYPE_SET_ORGANIZATION_FEATURE]
	Type *string `json:"type"`
}

// Validate validates this set organization feature request
func (m *SetOrganizationFeatureRequest) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateOrganizationID(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateParameters(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateTimestampMs(formats); err != nil {
		res = append(res, err)
	}

	if err := m.validateType(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SetOrganizationFeatureRequest) validateOrganizationID(formats strfmt.Registry) error {

	if err := validate.Required("organizationId", "body", m.OrganizationID); err != nil {
		return err
	}

	return nil
}

func (m *SetOrganizationFeatureRequest) validateParameters(formats strfmt.Registry) error {

	if err := validate.Required("parameters", "body", m.Parameters); err != nil {
		return err
	}

	if m.Parameters != nil {
		if err := m.Parameters.Validate(formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("parameters")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("parameters")
			}
			return err
		}
	}

	return nil
}

func (m *SetOrganizationFeatureRequest) validateTimestampMs(formats strfmt.Registry) error {

	if err := validate.Required("timestampMs", "body", m.TimestampMs); err != nil {
		return err
	}

	return nil
}

var setOrganizationFeatureRequestTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["ACTIVITY_TYPE_SET_ORGANIZATION_FEATURE"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		setOrganizationFeatureRequestTypeTypePropEnum = append(setOrganizationFeatureRequestTypeTypePropEnum, v)
	}
}

const (

	// SetOrganizationFeatureRequestTypeACTIVITYTYPESETORGANIZATIONFEATURE captures enum value "ACTIVITY_TYPE_SET_ORGANIZATION_FEATURE"
	SetOrganizationFeatureRequestTypeACTIVITYTYPESETORGANIZATIONFEATURE string = "ACTIVITY_TYPE_SET_ORGANIZATION_FEATURE"
)

// prop value enum
func (m *SetOrganizationFeatureRequest) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, setOrganizationFeatureRequestTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *SetOrganizationFeatureRequest) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", *m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this set organization feature request based on the context it is used
func (m *SetOrganizationFeatureRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateParameters(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *SetOrganizationFeatureRequest) contextValidateParameters(ctx context.Context, formats strfmt.Registry) error {

	if m.Parameters != nil {

		if err := m.Parameters.ContextValidate(ctx, formats); err != nil {
			if ve, ok := err.(*errors.Validation); ok {
				return ve.ValidateName("parameters")
			} else if ce, ok := err.(*errors.CompositeError); ok {
				return ce.ValidateName("parameters")
			}
			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *SetOrganizationFeatureRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *SetOrganizationFeatureRequest) UnmarshalBinary(b []byte) error {
	var res SetOrganizationFeatureRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}