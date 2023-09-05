// Code generated by go-swagger; DO NOT EDIT.

package private_keys

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// PublicAPIServiceGetPrivateKeyReader is a Reader for the PublicAPIServiceGetPrivateKey structure.
type PublicAPIServiceGetPrivateKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PublicAPIServiceGetPrivateKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPublicAPIServiceGetPrivateKeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPublicAPIServiceGetPrivateKeyDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPublicAPIServiceGetPrivateKeyOK creates a PublicAPIServiceGetPrivateKeyOK with default headers values
func NewPublicAPIServiceGetPrivateKeyOK() *PublicAPIServiceGetPrivateKeyOK {
	return &PublicAPIServiceGetPrivateKeyOK{}
}

/*
PublicAPIServiceGetPrivateKeyOK describes a response with status code 200, with default header values.

A successful response.
*/
type PublicAPIServiceGetPrivateKeyOK struct {
	Payload *models.V1GetPrivateKeyResponse
}

// IsSuccess returns true when this public Api service get private key o k response has a 2xx status code
func (o *PublicAPIServiceGetPrivateKeyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this public Api service get private key o k response has a 3xx status code
func (o *PublicAPIServiceGetPrivateKeyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this public Api service get private key o k response has a 4xx status code
func (o *PublicAPIServiceGetPrivateKeyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this public Api service get private key o k response has a 5xx status code
func (o *PublicAPIServiceGetPrivateKeyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this public Api service get private key o k response a status code equal to that given
func (o *PublicAPIServiceGetPrivateKeyOK) IsCode(code int) bool {
	return code == 200
}

func (o *PublicAPIServiceGetPrivateKeyOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/query/get_private_key][%d] publicApiServiceGetPrivateKeyOK  %+v", 200, o.Payload)
}

func (o *PublicAPIServiceGetPrivateKeyOK) String() string {
	return fmt.Sprintf("[POST /public/v1/query/get_private_key][%d] publicApiServiceGetPrivateKeyOK  %+v", 200, o.Payload)
}

func (o *PublicAPIServiceGetPrivateKeyOK) GetPayload() *models.V1GetPrivateKeyResponse {
	return o.Payload
}

func (o *PublicAPIServiceGetPrivateKeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1GetPrivateKeyResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPublicAPIServiceGetPrivateKeyDefault creates a PublicAPIServiceGetPrivateKeyDefault with default headers values
func NewPublicAPIServiceGetPrivateKeyDefault(code int) *PublicAPIServiceGetPrivateKeyDefault {
	return &PublicAPIServiceGetPrivateKeyDefault{
		_statusCode: code,
	}
}

/*
PublicAPIServiceGetPrivateKeyDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type PublicAPIServiceGetPrivateKeyDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// Code gets the status code for the public Api service get private key default response
func (o *PublicAPIServiceGetPrivateKeyDefault) Code() int {
	return o._statusCode
}

// IsSuccess returns true when this public Api service get private key default response has a 2xx status code
func (o *PublicAPIServiceGetPrivateKeyDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this public Api service get private key default response has a 3xx status code
func (o *PublicAPIServiceGetPrivateKeyDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this public Api service get private key default response has a 4xx status code
func (o *PublicAPIServiceGetPrivateKeyDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this public Api service get private key default response has a 5xx status code
func (o *PublicAPIServiceGetPrivateKeyDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this public Api service get private key default response a status code equal to that given
func (o *PublicAPIServiceGetPrivateKeyDefault) IsCode(code int) bool {
	return o._statusCode == code
}

func (o *PublicAPIServiceGetPrivateKeyDefault) Error() string {
	return fmt.Sprintf("[POST /public/v1/query/get_private_key][%d] PublicApiService_GetPrivateKey default  %+v", o._statusCode, o.Payload)
}

func (o *PublicAPIServiceGetPrivateKeyDefault) String() string {
	return fmt.Sprintf("[POST /public/v1/query/get_private_key][%d] PublicApiService_GetPrivateKey default  %+v", o._statusCode, o.Payload)
}

func (o *PublicAPIServiceGetPrivateKeyDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *PublicAPIServiceGetPrivateKeyDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
