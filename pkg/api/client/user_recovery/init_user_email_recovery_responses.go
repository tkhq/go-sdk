// Code generated by go-swagger; DO NOT EDIT.

package user_recovery

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// InitUserEmailRecoveryReader is a Reader for the InitUserEmailRecovery structure.
type InitUserEmailRecoveryReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *InitUserEmailRecoveryReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewInitUserEmailRecoveryOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/init_user_email_recovery] InitUserEmailRecovery", response, response.Code())
	}
}

// NewInitUserEmailRecoveryOK creates a InitUserEmailRecoveryOK with default headers values
func NewInitUserEmailRecoveryOK() *InitUserEmailRecoveryOK {
	return &InitUserEmailRecoveryOK{}
}

/*
InitUserEmailRecoveryOK describes a response with status code 200, with default header values.

A successful response.
*/
type InitUserEmailRecoveryOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this init user email recovery o k response has a 2xx status code
func (o *InitUserEmailRecoveryOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this init user email recovery o k response has a 3xx status code
func (o *InitUserEmailRecoveryOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this init user email recovery o k response has a 4xx status code
func (o *InitUserEmailRecoveryOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this init user email recovery o k response has a 5xx status code
func (o *InitUserEmailRecoveryOK) IsServerError() bool {
	return false
}

// IsCode returns true when this init user email recovery o k response a status code equal to that given
func (o *InitUserEmailRecoveryOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the init user email recovery o k response
func (o *InitUserEmailRecoveryOK) Code() int {
	return 200
}

func (o *InitUserEmailRecoveryOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /public/v1/submit/init_user_email_recovery][%d] initUserEmailRecoveryOK %s", 200, payload)
}

func (o *InitUserEmailRecoveryOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /public/v1/submit/init_user_email_recovery][%d] initUserEmailRecoveryOK %s", 200, payload)
}

func (o *InitUserEmailRecoveryOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *InitUserEmailRecoveryOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
