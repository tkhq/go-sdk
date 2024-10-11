// Code generated by go-swagger; DO NOT EDIT.

package user_tags

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

// UpdateUserTagReader is a Reader for the UpdateUserTag structure.
type UpdateUserTagReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *UpdateUserTagReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewUpdateUserTagOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/update_user_tag] UpdateUserTag", response, response.Code())
	}
}

// NewUpdateUserTagOK creates a UpdateUserTagOK with default headers values
func NewUpdateUserTagOK() *UpdateUserTagOK {
	return &UpdateUserTagOK{}
}

/*
UpdateUserTagOK describes a response with status code 200, with default header values.

A successful response.
*/
type UpdateUserTagOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this update user tag o k response has a 2xx status code
func (o *UpdateUserTagOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this update user tag o k response has a 3xx status code
func (o *UpdateUserTagOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this update user tag o k response has a 4xx status code
func (o *UpdateUserTagOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this update user tag o k response has a 5xx status code
func (o *UpdateUserTagOK) IsServerError() bool {
	return false
}

// IsCode returns true when this update user tag o k response a status code equal to that given
func (o *UpdateUserTagOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the update user tag o k response
func (o *UpdateUserTagOK) Code() int {
	return 200
}

func (o *UpdateUserTagOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /public/v1/submit/update_user_tag][%d] updateUserTagOK %s", 200, payload)
}

func (o *UpdateUserTagOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /public/v1/submit/update_user_tag][%d] updateUserTagOK %s", 200, payload)
}

func (o *UpdateUserTagOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *UpdateUserTagOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
