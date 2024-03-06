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

// ImportPrivateKeyReader is a Reader for the ImportPrivateKey structure.
type ImportPrivateKeyReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ImportPrivateKeyReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewImportPrivateKeyOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/import_private_key] ImportPrivateKey", response, response.Code())
	}
}

// NewImportPrivateKeyOK creates a ImportPrivateKeyOK with default headers values
func NewImportPrivateKeyOK() *ImportPrivateKeyOK {
	return &ImportPrivateKeyOK{}
}

/*
ImportPrivateKeyOK describes a response with status code 200, with default header values.

A successful response.
*/
type ImportPrivateKeyOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this import private key o k response has a 2xx status code
func (o *ImportPrivateKeyOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this import private key o k response has a 3xx status code
func (o *ImportPrivateKeyOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this import private key o k response has a 4xx status code
func (o *ImportPrivateKeyOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this import private key o k response has a 5xx status code
func (o *ImportPrivateKeyOK) IsServerError() bool {
	return false
}

// IsCode returns true when this import private key o k response a status code equal to that given
func (o *ImportPrivateKeyOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the import private key o k response
func (o *ImportPrivateKeyOK) Code() int {
	return 200
}

func (o *ImportPrivateKeyOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/import_private_key][%d] importPrivateKeyOK  %+v", 200, o.Payload)
}

func (o *ImportPrivateKeyOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/import_private_key][%d] importPrivateKeyOK  %+v", 200, o.Payload)
}

func (o *ImportPrivateKeyOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *ImportPrivateKeyOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}