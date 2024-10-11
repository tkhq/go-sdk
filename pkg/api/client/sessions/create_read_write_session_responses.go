// Code generated by go-swagger; DO NOT EDIT.

package sessions

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

// CreateReadWriteSessionReader is a Reader for the CreateReadWriteSession structure.
type CreateReadWriteSessionReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *CreateReadWriteSessionReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewCreateReadWriteSessionOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/create_read_write_session] CreateReadWriteSession", response, response.Code())
	}
}

// NewCreateReadWriteSessionOK creates a CreateReadWriteSessionOK with default headers values
func NewCreateReadWriteSessionOK() *CreateReadWriteSessionOK {
	return &CreateReadWriteSessionOK{}
}

/*
CreateReadWriteSessionOK describes a response with status code 200, with default header values.

A successful response.
*/
type CreateReadWriteSessionOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this create read write session o k response has a 2xx status code
func (o *CreateReadWriteSessionOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this create read write session o k response has a 3xx status code
func (o *CreateReadWriteSessionOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this create read write session o k response has a 4xx status code
func (o *CreateReadWriteSessionOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this create read write session o k response has a 5xx status code
func (o *CreateReadWriteSessionOK) IsServerError() bool {
	return false
}

// IsCode returns true when this create read write session o k response a status code equal to that given
func (o *CreateReadWriteSessionOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the create read write session o k response
func (o *CreateReadWriteSessionOK) Code() int {
	return 200
}

func (o *CreateReadWriteSessionOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /public/v1/submit/create_read_write_session][%d] createReadWriteSessionOK %s", 200, payload)
}

func (o *CreateReadWriteSessionOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /public/v1/submit/create_read_write_session][%d] createReadWriteSessionOK %s", 200, payload)
}

func (o *CreateReadWriteSessionOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *CreateReadWriteSessionOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
