// Code generated by go-swagger; DO NOT EDIT.

package user_tags

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// PublicAPIServiceCreateUserTagReader is a Reader for the PublicAPIServiceCreateUserTag structure.
type PublicAPIServiceCreateUserTagReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PublicAPIServiceCreateUserTagReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPublicAPIServiceCreateUserTagOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPublicAPIServiceCreateUserTagDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPublicAPIServiceCreateUserTagOK creates a PublicAPIServiceCreateUserTagOK with default headers values
func NewPublicAPIServiceCreateUserTagOK() *PublicAPIServiceCreateUserTagOK {
	return &PublicAPIServiceCreateUserTagOK{}
}

/*
PublicAPIServiceCreateUserTagOK describes a response with status code 200, with default header values.

A successful response.
*/
type PublicAPIServiceCreateUserTagOK struct {
	Payload *models.V1ActivityResponse
}

// IsSuccess returns true when this public Api service create user tag o k response has a 2xx status code
func (o *PublicAPIServiceCreateUserTagOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this public Api service create user tag o k response has a 3xx status code
func (o *PublicAPIServiceCreateUserTagOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this public Api service create user tag o k response has a 4xx status code
func (o *PublicAPIServiceCreateUserTagOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this public Api service create user tag o k response has a 5xx status code
func (o *PublicAPIServiceCreateUserTagOK) IsServerError() bool {
	return false
}

// IsCode returns true when this public Api service create user tag o k response a status code equal to that given
func (o *PublicAPIServiceCreateUserTagOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the public Api service create user tag o k response
func (o *PublicAPIServiceCreateUserTagOK) Code() int {
	return 200
}

func (o *PublicAPIServiceCreateUserTagOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/create_user_tag][%d] publicApiServiceCreateUserTagOK  %+v", 200, o.Payload)
}

func (o *PublicAPIServiceCreateUserTagOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/create_user_tag][%d] publicApiServiceCreateUserTagOK  %+v", 200, o.Payload)
}

func (o *PublicAPIServiceCreateUserTagOK) GetPayload() *models.V1ActivityResponse {
	return o.Payload
}

func (o *PublicAPIServiceCreateUserTagOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPublicAPIServiceCreateUserTagDefault creates a PublicAPIServiceCreateUserTagDefault with default headers values
func NewPublicAPIServiceCreateUserTagDefault(code int) *PublicAPIServiceCreateUserTagDefault {
	return &PublicAPIServiceCreateUserTagDefault{
		_statusCode: code,
	}
}

/*
PublicAPIServiceCreateUserTagDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type PublicAPIServiceCreateUserTagDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this public Api service create user tag default response has a 2xx status code
func (o *PublicAPIServiceCreateUserTagDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this public Api service create user tag default response has a 3xx status code
func (o *PublicAPIServiceCreateUserTagDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this public Api service create user tag default response has a 4xx status code
func (o *PublicAPIServiceCreateUserTagDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this public Api service create user tag default response has a 5xx status code
func (o *PublicAPIServiceCreateUserTagDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this public Api service create user tag default response a status code equal to that given
func (o *PublicAPIServiceCreateUserTagDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the public Api service create user tag default response
func (o *PublicAPIServiceCreateUserTagDefault) Code() int {
	return o._statusCode
}

func (o *PublicAPIServiceCreateUserTagDefault) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/create_user_tag][%d] PublicApiService_CreateUserTag default  %+v", o._statusCode, o.Payload)
}

func (o *PublicAPIServiceCreateUserTagDefault) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/create_user_tag][%d] PublicApiService_CreateUserTag default  %+v", o._statusCode, o.Payload)
}

func (o *PublicAPIServiceCreateUserTagDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *PublicAPIServiceCreateUserTagDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
