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

// CreateReadWriteSessionRequest create read write session request
//
// swagger:model CreateReadWriteSessionRequest
type CreateReadWriteSessionRequest struct {

	// Unique identifier for a given Organization.
	// Required: true
	OrganizationID *string `json:"organizationId"`

	// parameters
	// Required: true
	Parameters *CreateReadWriteSessionIntentV2 `json:"parameters"`

	// Timestamp (in milliseconds) of the request, used to verify liveness of user requests.
	// Required: true
	TimestampMs *string `json:"timestampMs"`

	// type
	// Required: true
	// Enum: [ACTIVITY_TYPE_CREATE_READ_WRITE_SESSION_V2]
	Type *string `json:"type"`
}

// Validate validates this create read write session request
func (m *CreateReadWriteSessionRequest) Validate(formats strfmt.Registry) error {
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

func (m *CreateReadWriteSessionRequest) validateOrganizationID(formats strfmt.Registry) error {

	if err := validate.Required("organizationId", "body", m.OrganizationID); err != nil {
		return err
	}

	return nil
}

func (m *CreateReadWriteSessionRequest) validateParameters(formats strfmt.Registry) error {

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

func (m *CreateReadWriteSessionRequest) validateTimestampMs(formats strfmt.Registry) error {

	if err := validate.Required("timestampMs", "body", m.TimestampMs); err != nil {
		return err
	}

	return nil
}

var createReadWriteSessionRequestTypeTypePropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["ACTIVITY_TYPE_CREATE_READ_WRITE_SESSION_V2"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		createReadWriteSessionRequestTypeTypePropEnum = append(createReadWriteSessionRequestTypeTypePropEnum, v)
	}
}

const (

	// CreateReadWriteSessionRequestTypeACTIVITYTYPECREATEREADWRITESESSIONV2 captures enum value "ACTIVITY_TYPE_CREATE_READ_WRITE_SESSION_V2"
	CreateReadWriteSessionRequestTypeACTIVITYTYPECREATEREADWRITESESSIONV2 string = "ACTIVITY_TYPE_CREATE_READ_WRITE_SESSION_V2"
)

// prop value enum
func (m *CreateReadWriteSessionRequest) validateTypeEnum(path, location string, value string) error {
	if err := validate.EnumCase(path, location, value, createReadWriteSessionRequestTypeTypePropEnum, true); err != nil {
		return err
	}
	return nil
}

func (m *CreateReadWriteSessionRequest) validateType(formats strfmt.Registry) error {

	if err := validate.Required("type", "body", m.Type); err != nil {
		return err
	}

	// value enum
	if err := m.validateTypeEnum("type", "body", *m.Type); err != nil {
		return err
	}

	return nil
}

// ContextValidate validate this create read write session request based on the context it is used
func (m *CreateReadWriteSessionRequest) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidateParameters(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *CreateReadWriteSessionRequest) contextValidateParameters(ctx context.Context, formats strfmt.Registry) error {

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
func (m *CreateReadWriteSessionRequest) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *CreateReadWriteSessionRequest) UnmarshalBinary(b []byte) error {
	var res CreateReadWriteSessionRequest
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
