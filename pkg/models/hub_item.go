// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// HubItem HubItem
//
// swagger:model HubItem
type HubItem struct {

	// name of the hub item
	Name string `json:"name,omitempty"`

	// status of the hub item (official, custom, tainted, etc.)
	Status string `json:"status,omitempty"`

	// version of the hub item
	Version string `json:"version,omitempty"`
}

// Validate validates this hub item
func (m *HubItem) Validate(formats strfmt.Registry) error {
	return nil
}

// ContextValidate validates this hub item based on context it is used
func (m *HubItem) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}

// MarshalBinary interface implementation
func (m *HubItem) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *HubItem) UnmarshalBinary(b []byte) error {
	var res HubItem
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
