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

// DeleteAPIKeysReader is a Reader for the DeleteAPIKeys structure.
type DeleteAPIKeysReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeleteAPIKeysReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeleteAPIKeysOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewDeleteAPIKeysOK creates a DeleteAPIKeysOK with default headers values
func NewDeleteAPIKeysOK() *DeleteAPIKeysOK {
	return &DeleteAPIKeysOK{}
}

/*
DeleteAPIKeysOK describes a response with status code 200, with default header values.

A successful response.
*/
type DeleteAPIKeysOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this delete Api keys o k response has a 2xx status code
func (o *DeleteAPIKeysOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete Api keys o k response has a 3xx status code
func (o *DeleteAPIKeysOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete Api keys o k response has a 4xx status code
func (o *DeleteAPIKeysOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete Api keys o k response has a 5xx status code
func (o *DeleteAPIKeysOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete Api keys o k response a status code equal to that given
func (o *DeleteAPIKeysOK) IsCode(code int) bool {
	return code == 200
}

func (o *DeleteAPIKeysOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/delete_api_keys][%d] deleteApiKeysOK  %+v", 200, o.Payload)
}

func (o *DeleteAPIKeysOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/delete_api_keys][%d] deleteApiKeysOK  %+v", 200, o.Payload)
}

func (o *DeleteAPIKeysOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *DeleteAPIKeysOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
