// Code generated by go-swagger; DO NOT EDIT.

package wallets

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

// ExportWalletAccountReader is a Reader for the ExportWalletAccount structure.
type ExportWalletAccountReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ExportWalletAccountReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewExportWalletAccountOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, runtime.NewAPIError("[POST /public/v1/submit/export_wallet_account] ExportWalletAccount", response, response.Code())
	}
}

// NewExportWalletAccountOK creates a ExportWalletAccountOK with default headers values
func NewExportWalletAccountOK() *ExportWalletAccountOK {
	return &ExportWalletAccountOK{}
}

/*
ExportWalletAccountOK describes a response with status code 200, with default header values.

A successful response.
*/
type ExportWalletAccountOK struct {
	Payload *models.ActivityResponse
}

// IsSuccess returns true when this export wallet account o k response has a 2xx status code
func (o *ExportWalletAccountOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this export wallet account o k response has a 3xx status code
func (o *ExportWalletAccountOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this export wallet account o k response has a 4xx status code
func (o *ExportWalletAccountOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this export wallet account o k response has a 5xx status code
func (o *ExportWalletAccountOK) IsServerError() bool {
	return false
}

// IsCode returns true when this export wallet account o k response a status code equal to that given
func (o *ExportWalletAccountOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the export wallet account o k response
func (o *ExportWalletAccountOK) Code() int {
	return 200
}

func (o *ExportWalletAccountOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /public/v1/submit/export_wallet_account][%d] exportWalletAccountOK %s", 200, payload)
}

func (o *ExportWalletAccountOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /public/v1/submit/export_wallet_account][%d] exportWalletAccountOK %s", 200, payload)
}

func (o *ExportWalletAccountOK) GetPayload() *models.ActivityResponse {
	return o.Payload
}

func (o *ExportWalletAccountOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.ActivityResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
