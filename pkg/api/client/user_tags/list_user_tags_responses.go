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

// ListUserTagsReader is a Reader for the ListUserTags structure.
type ListUserTagsReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ListUserTagsReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewListUserTagsOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/query/list_user_tags] ListUserTags", response, response.Code())
	}
}

// NewListUserTagsOK creates a ListUserTagsOK with default headers values
func NewListUserTagsOK() *ListUserTagsOK {
	return &ListUserTagsOK{}
}

/*
ListUserTagsOK describes a response with status code 200, with default header values.

A successful response.
*/
type ListUserTagsOK struct {
	Payload *models.ListUserTagsResponse
}

// IsSuccess returns true when this list user tags o k response has a 2xx status code
func (o *ListUserTagsOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this list user tags o k response has a 3xx status code
func (o *ListUserTagsOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this list user tags o k response has a 4xx status code
func (o *ListUserTagsOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this list user tags o k response has a 5xx status code
func (o *ListUserTagsOK) IsServerError() bool {
	return false
}

// IsCode returns true when this list user tags o k response a status code equal to that given
func (o *ListUserTagsOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the list user tags o k response
func (o *ListUserTagsOK) Code() int {
	return 200
}

func (o *ListUserTagsOK) Error() string {
	return fmt.Sprintf("[POST /public/v1/query/list_user_tags][%d] listUserTagsOK  %+v", 200, o.Payload)
}

func (o *ListUserTagsOK) String() string {
	return fmt.Sprintf("[POST /public/v1/query/list_user_tags][%d] listUserTagsOK  %+v", 200, o.Payload)
}

func (o *ListUserTagsOK) GetPayload() *models.ListUserTagsResponse {
	return o.Payload
}

func (o *ListUserTagsOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ListUserTagsResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
