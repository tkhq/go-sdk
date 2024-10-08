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

// FeatureName feature name
//
// swagger:model FeatureName
type FeatureName string

func NewFeatureName(value FeatureName) *FeatureName {
	return &value
}

// Pointer returns a pointer to a freshly-allocated FeatureName.
func (m FeatureName) Pointer() *FeatureName {
	return &m
}

const (

	// FeatureNameRootUserEmailRecovery captures enum value "FEATURE_NAME_ROOT_USER_EMAIL_RECOVERY"
	FeatureNameRootUserEmailRecovery FeatureName = "FEATURE_NAME_ROOT_USER_EMAIL_RECOVERY"

	// FeatureNameWebauthnOrigins captures enum value "FEATURE_NAME_WEBAUTHN_ORIGINS"
	FeatureNameWebauthnOrigins FeatureName = "FEATURE_NAME_WEBAUTHN_ORIGINS"

	// FeatureNameEmailAuth captures enum value "FEATURE_NAME_EMAIL_AUTH"
	FeatureNameEmailAuth FeatureName = "FEATURE_NAME_EMAIL_AUTH"

	// FeatureNameEmailRecovery captures enum value "FEATURE_NAME_EMAIL_RECOVERY"
	FeatureNameEmailRecovery FeatureName = "FEATURE_NAME_EMAIL_RECOVERY"

	// FeatureNameWebhook captures enum value "FEATURE_NAME_WEBHOOK"
	FeatureNameWebhook FeatureName = "FEATURE_NAME_WEBHOOK"

	// FeatureNameSmsAuth captures enum value "FEATURE_NAME_SMS_AUTH"
	FeatureNameSmsAuth FeatureName = "FEATURE_NAME_SMS_AUTH"

	// FeatureNameOtpEmailAuth captures enum value "FEATURE_NAME_OTP_EMAIL_AUTH"
	FeatureNameOtpEmailAuth FeatureName = "FEATURE_NAME_OTP_EMAIL_AUTH"
)

// for schema
var FeatureNameEnum []FeatureName

func init() {
	var res []FeatureName
	if err := json.Unmarshal([]byte(`["FEATURE_NAME_ROOT_USER_EMAIL_RECOVERY","FEATURE_NAME_WEBAUTHN_ORIGINS","FEATURE_NAME_EMAIL_AUTH","FEATURE_NAME_EMAIL_RECOVERY","FEATURE_NAME_WEBHOOK","FEATURE_NAME_SMS_AUTH","FEATURE_NAME_OTP_EMAIL_AUTH"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		FeatureNameEnum = append(FeatureNameEnum, v)
	}
}

func (m FeatureName) validateFeatureNameEnum(path, location string, value FeatureName) error {
	if err := validate.EnumCase(path, location, value, FeatureNameEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this feature name
func (m FeatureName) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateFeatureNameEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this feature name based on context it is used
func (m FeatureName) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
