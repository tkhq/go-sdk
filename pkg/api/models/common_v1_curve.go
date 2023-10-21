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

// CommonV1Curve common v1 curve
//
// swagger:model common.v1.Curve
type CommonV1Curve string

func NewCommonV1Curve(value CommonV1Curve) *CommonV1Curve {
	return &value
}

// Pointer returns a pointer to a freshly-allocated CommonV1Curve.
func (m CommonV1Curve) Pointer() *CommonV1Curve {
	return &m
}

const (

	// CommonV1CurveCURVESECP256K1 captures enum value "CURVE_SECP256K1"
	CommonV1CurveCURVESECP256K1 CommonV1Curve = "CURVE_SECP256K1"

	// CommonV1CurveCURVEED25519 captures enum value "CURVE_ED25519"
	CommonV1CurveCURVEED25519 CommonV1Curve = "CURVE_ED25519"
)

// for schema
var commonV1CurveEnum []interface{}

func init() {
	var res []CommonV1Curve
	if err := json.Unmarshal([]byte(`["CURVE_SECP256K1","CURVE_ED25519"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		commonV1CurveEnum = append(commonV1CurveEnum, v)
	}
}

func (m CommonV1Curve) validateCommonV1CurveEnum(path, location string, value CommonV1Curve) error {
	if err := validate.EnumCase(path, location, value, commonV1CurveEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this common v1 curve
func (m CommonV1Curve) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateCommonV1CurveEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this common v1 curve based on context it is used
func (m CommonV1Curve) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
