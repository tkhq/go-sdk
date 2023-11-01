// Code generated by go-swagger; DO NOT EDIT.

package features

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// SetOrganizationFeatureReader is a Reader for the SetOrganizationFeature structure.
type SetOrganizationFeatureReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *SetOrganizationFeatureReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewSetOrganizationFeatureOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/set_organization_feature] SetOrganizationFeature", response, response.Code())
	}
}

// NewSetOrganizationFeatureOK creates a SetOrganizationFeatureOK with default headers values
func NewSetOrganizationFeatureOK() *SetOrganizationFeatureOK {
	return &SetOrganizationFeatureOK{}
}

/*
SetOrganizationFeatureOK describes a response with status code 200, with default header values.

A successful response.
*/
type SetOrganizationFeatureOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this set organization feature o k response has a 2xx status code
func (o *SetOrganizationFeatureOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this set organization feature o k response has a 3xx status code
func (o *SetOrganizationFeatureOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this set organization feature o k response has a 4xx status code
func (o *SetOrganizationFeatureOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this set organization feature o k response has a 5xx status code
func (o *SetOrganizationFeatureOK) IsServerError() bool {
	return false
}

// IsCode returns true when this set organization feature o k response a status code equal to that given
func (o *SetOrganizationFeatureOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the set organization feature o k response
func (o *SetOrganizationFeatureOK) Code() int {
	return 200
}

func (o *SetOrganizationFeatureOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/set_organization_feature][%d] setOrganizationFeatureOK  %+v", 200, o.Payload)
}

func (o *SetOrganizationFeatureOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/set_organization_feature][%d] setOrganizationFeatureOK  %+v", 200, o.Payload)
}

func (o *SetOrganizationFeatureOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *SetOrganizationFeatureOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}