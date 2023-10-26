// Code generated by go-swagger; DO NOT EDIT.

package private_key_tags

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// UpdatePrivateKeyTagReader is a Reader for the UpdatePrivateKeyTag structure.
type UpdatePrivateKeyTagReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdatePrivateKeyTagReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdatePrivateKeyTagOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewUpdatePrivateKeyTagOK creates a UpdatePrivateKeyTagOK with default headers values
func NewUpdatePrivateKeyTagOK() *UpdatePrivateKeyTagOK {
	return &UpdatePrivateKeyTagOK{}
}

/*
UpdatePrivateKeyTagOK describes a response with status code 200, with default header values.

A successful response.
*/
type UpdatePrivateKeyTagOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this update private key tag o k response has a 2xx status code
func (o *UpdatePrivateKeyTagOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update private key tag o k response has a 3xx status code
func (o *UpdatePrivateKeyTagOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update private key tag o k response has a 4xx status code
func (o *UpdatePrivateKeyTagOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update private key tag o k response has a 5xx status code
func (o *UpdatePrivateKeyTagOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update private key tag o k response a status code equal to that given
func (o *UpdatePrivateKeyTagOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update private key tag o k response
func (o *UpdatePrivateKeyTagOK) Code() int {
	return 200
}

func (o *UpdatePrivateKeyTagOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_private_key_tag][%d] updatePrivateKeyTagOK  %+v", 200, o.Payload)
}

func (o *UpdatePrivateKeyTagOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/update_private_key_tag][%d] updatePrivateKeyTagOK  %+v", 200, o.Payload)
}

func (o *UpdatePrivateKeyTagOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *UpdatePrivateKeyTagOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
