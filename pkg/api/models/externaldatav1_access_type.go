// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// Externaldatav1AccessType externaldatav1 access type
//
// swagger:model externaldatav1AccessType
type Externaldatav1AccessType string

func NewExternaldatav1AccessType(value Externaldatav1AccessType) *Externaldatav1AccessType {
	return &value
}

// Pointer returns a pointer to a freshly-allocated Externaldatav1AccessType.
func (m Externaldatav1AccessType) Pointer() *Externaldatav1AccessType {
	return &m
}

const (

	// Externaldatav1AccessTypeACCESSTYPEWEB captures enum value "ACCESS_TYPE_WEB"
	Externaldatav1AccessTypeACCESSTYPEWEB Externaldatav1AccessType = "ACCESS_TYPE_WEB"

	// Externaldatav1AccessTypeACCESSTYPEAPI captures enum value "ACCESS_TYPE_API"
	Externaldatav1AccessTypeACCESSTYPEAPI Externaldatav1AccessType = "ACCESS_TYPE_API"

	// Externaldatav1AccessTypeACCESSTYPEALL captures enum value "ACCESS_TYPE_ALL"
	Externaldatav1AccessTypeACCESSTYPEALL Externaldatav1AccessType = "ACCESS_TYPE_ALL"
)

// for schema
var externaldatav1AccessTypeEnum []interface{}

func init() {
	var res []Externaldatav1AccessType
	if err := json.Unmarshal([]byte(`["ACCESS_TYPE_WEB","ACCESS_TYPE_API","ACCESS_TYPE_ALL"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		externaldatav1AccessTypeEnum = append(externaldatav1AccessTypeEnum, v)
	}
}

func (m Externaldatav1AccessType) validateExternaldatav1AccessTypeEnum(path, location string, value Externaldatav1AccessType) error {
	if err := validate.EnumCase(path, location, value, externaldatav1AccessTypeEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this externaldatav1 access type
func (m Externaldatav1AccessType) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateExternaldatav1AccessTypeEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this externaldatav1 access type based on context it is used
func (m Externaldatav1AccessType) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
