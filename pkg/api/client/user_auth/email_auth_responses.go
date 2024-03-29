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

// EmailAuthReader is a Reader for the EmailAuth structure.
type EmailAuthReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *EmailAuthReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewEmailAuthOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/email_auth] EmailAuth", response, response.Code())
	}
}

// NewEmailAuthOK creates a EmailAuthOK with default headers values
func NewEmailAuthOK() *EmailAuthOK {
	return &EmailAuthOK{}
}

/*
EmailAuthOK describes a response with status code 200, with default header values.

A successful response.
*/
type EmailAuthOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this email auth o k response has a 2xx status code
func (o *EmailAuthOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this email auth o k response has a 3xx status code
func (o *EmailAuthOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this email auth o k response has a 4xx status code
func (o *EmailAuthOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this email auth o k response has a 5xx status code
func (o *EmailAuthOK) IsServerError() bool {
	return false
}

// IsCode returns true when this email auth o k response a status code equal to that given
func (o *EmailAuthOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the email auth o k response
func (o *EmailAuthOK) Code() int {
	return 200
}

func (o *EmailAuthOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/email_auth][%d] emailAuthOK  %+v", 200, o.Payload)
}

func (o *EmailAuthOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/email_auth][%d] emailAuthOK  %+v", 200, o.Payload)
}

func (o *EmailAuthOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *EmailAuthOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
