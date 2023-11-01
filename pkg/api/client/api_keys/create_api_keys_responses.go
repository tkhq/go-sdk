// Code generated by go-swagger; DO NOT EDIT.

package api_keys

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/tkhq/go-sdk/pkg/api/models"
)

// CreateAPIKeysReader is a Reader for the CreateAPIKeys structure.
type CreateAPIKeysReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateAPIKeysReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateAPIKeysOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/create_api_keys] CreateApiKeys", response, response.Code())
	}
}

// NewCreateAPIKeysOK creates a CreateAPIKeysOK with default headers values
func NewCreateAPIKeysOK() *CreateAPIKeysOK {
	return &CreateAPIKeysOK{}
}

/*
CreateAPIKeysOK describes a response with status code 200, with default header values.

A successful response.
*/
type CreateAPIKeysOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this create Api keys o k response has a 2xx status code
func (o *CreateAPIKeysOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create Api keys o k response has a 3xx status code
func (o *CreateAPIKeysOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create Api keys o k response has a 4xx status code
func (o *CreateAPIKeysOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this create Api keys o k response has a 5xx status code
func (o *CreateAPIKeysOK) IsServerError() bool {
	return false
}

// IsCode returns true when this create Api keys o k response a status code equal to that given
func (o *CreateAPIKeysOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the create Api keys o k response
func (o *CreateAPIKeysOK) Code() int {
	return 200
}

func (o *CreateAPIKeysOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/create_api_keys][%d] createApiKeysOK  %+v", 200, o.Payload)
}

func (o *CreateAPIKeysOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/create_api_keys][%d] createApiKeysOK  %+v", 200, o.Payload)
}

func (o *CreateAPIKeysOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *CreateAPIKeysOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}