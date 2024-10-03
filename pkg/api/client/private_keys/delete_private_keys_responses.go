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

// DeletePrivateKeysReader is a Reader for the DeletePrivateKeys structure.
type DeletePrivateKeysReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *DeletePrivateKeysReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewDeletePrivateKeysOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/delete_private_keys] DeletePrivateKeys", response, response.Code())
	}
}

// NewDeletePrivateKeysOK creates a DeletePrivateKeysOK with default headers values
func NewDeletePrivateKeysOK() *DeletePrivateKeysOK {
	return &DeletePrivateKeysOK{}
}

/*
DeletePrivateKeysOK describes a response with status code 200, with default header values.

A successful response.
*/
type DeletePrivateKeysOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this delete private keys o k response has a 2xx status code
func (o *DeletePrivateKeysOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this delete private keys o k response has a 3xx status code
func (o *DeletePrivateKeysOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this delete private keys o k response has a 4xx status code
func (o *DeletePrivateKeysOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this delete private keys o k response has a 5xx status code
func (o *DeletePrivateKeysOK) IsServerError() bool {
	return false
}

// IsCode returns true when this delete private keys o k response a status code equal to that given
func (o *DeletePrivateKeysOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the delete private keys o k response
func (o *DeletePrivateKeysOK) Code() int {
	return 200
}

func (o *DeletePrivateKeysOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/submit/delete_private_keys][%d] deletePrivateKeysOK  %+v", 200, o.Payload)
}

func (o *DeletePrivateKeysOK) String() string {
	return fmt.Sprintf("[POST /public/v1/submit/delete_private_keys][%d] deletePrivateKeysOK  %+v", 200, o.Payload)
}

func (o *DeletePrivateKeysOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *DeletePrivateKeysOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}