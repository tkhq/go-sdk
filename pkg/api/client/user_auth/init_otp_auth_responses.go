// Code generated by go-swagger; DO NOT EDIT.

package user_auth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// InitOtpAuthReader is a Reader for the InitOtpAuth structure.
type InitOtpAuthReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *InitOtpAuthReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewInitOtpAuthOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/init_otp_auth] InitOtpAuth", response, response.Code())
	}
}

// NewInitOtpAuthOK creates a InitOtpAuthOK with default headers values
func NewInitOtpAuthOK() *InitOtpAuthOK {
	return &InitOtpAuthOK{}
}

/*
InitOtpAuthOK describes a response with status code 200, with default header values.

A successful response.
*/
type InitOtpAuthOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this init otp auth o k response has a 2xx status code
func (o *InitOtpAuthOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this init otp auth o k response has a 3xx status code
func (o *InitOtpAuthOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this init otp auth o k response has a 4xx status code
func (o *InitOtpAuthOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this init otp auth o k response has a 5xx status code
func (o *InitOtpAuthOK) IsServerError() bool {
	return false
}

// IsCode returns true when this init otp auth o k response a status code equal to that given
func (o *InitOtpAuthOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the init otp auth o k response
func (o *InitOtpAuthOK) Code() int {
	return 200
}

func (o *InitOtpAuthOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/init_otp_auth][%d] initOtpAuthOK  %+v", 200, o.Payload)
}

func (o *InitOtpAuthOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/init_otp_auth][%d] initOtpAuthOK  %+v", 200, o.Payload)
}

func (o *InitOtpAuthOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *InitOtpAuthOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
