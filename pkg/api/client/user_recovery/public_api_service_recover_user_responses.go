// Code generated by go-swagger; DO NOT EDIT.

package user_recovery

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// PublicAPIServiceRecoverUserReader is a Reader for the PublicAPIServiceRecoverUser structure.
type PublicAPIServiceRecoverUserReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *PublicAPIServiceRecoverUserReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewPublicAPIServiceRecoverUserOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewPublicAPIServiceRecoverUserDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewPublicAPIServiceRecoverUserOK creates a PublicAPIServiceRecoverUserOK with default headers values
func NewPublicAPIServiceRecoverUserOK() *PublicAPIServiceRecoverUserOK {
	return &PublicAPIServiceRecoverUserOK{}
}

/*
PublicAPIServiceRecoverUserOK describes a response with status code 200, with default header values.

A successful response.
*/
type PublicAPIServiceRecoverUserOK struct {
	Payload *models.V1ActivityResponse
}

// IsSuccess returns true when this public Api service recover user o k response has a 2xx status code
func (o *PublicAPIServiceRecoverUserOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this public Api service recover user o k response has a 3xx status code
func (o *PublicAPIServiceRecoverUserOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this public Api service recover user o k response has a 4xx status code
func (o *PublicAPIServiceRecoverUserOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this public Api service recover user o k response has a 5xx status code
func (o *PublicAPIServiceRecoverUserOK) IsServerError() bool {
	return false
}

// IsCode returns true when this public Api service recover user o k response a status code equal to that given
func (o *PublicAPIServiceRecoverUserOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the public Api service recover user o k response
func (o *PublicAPIServiceRecoverUserOK) Code() int {
	return 200
}

func (o *PublicAPIServiceRecoverUserOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/recover_user][%d] publicApiServiceRecoverUserOK  %+v", 200, o.Payload)
}

func (o *PublicAPIServiceRecoverUserOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/recover_user][%d] publicApiServiceRecoverUserOK  %+v", 200, o.Payload)
}

func (o *PublicAPIServiceRecoverUserOK) GetPayload() *models.V1ActivityResponse {
	return o.Payload
}

func (o *PublicAPIServiceRecoverUserOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewPublicAPIServiceRecoverUserDefault creates a PublicAPIServiceRecoverUserDefault with default headers values
func NewPublicAPIServiceRecoverUserDefault(code int) *PublicAPIServiceRecoverUserDefault {
	return &PublicAPIServiceRecoverUserDefault{
		_statusCode: code,
	}
}

/*
PublicAPIServiceRecoverUserDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type PublicAPIServiceRecoverUserDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this public Api service recover user default response has a 2xx status code
func (o *PublicAPIServiceRecoverUserDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this public Api service recover user default response has a 3xx status code
func (o *PublicAPIServiceRecoverUserDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this public Api service recover user default response has a 4xx status code
func (o *PublicAPIServiceRecoverUserDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this public Api service recover user default response has a 5xx status code
func (o *PublicAPIServiceRecoverUserDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this public Api service recover user default response a status code equal to that given
func (o *PublicAPIServiceRecoverUserDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the public Api service recover user default response
func (o *PublicAPIServiceRecoverUserDefault) Code() int {
	return o._statusCode
}

func (o *PublicAPIServiceRecoverUserDefault) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/recover_user][%d] PublicApiService_RecoverUser default  %+v", o._statusCode, o.Payload)
}

func (o *PublicAPIServiceRecoverUserDefault) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/recover_user][%d] PublicApiService_RecoverUser default  %+v", o._statusCode, o.Payload)
}

func (o *PublicAPIServiceRecoverUserDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *PublicAPIServiceRecoverUserDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
