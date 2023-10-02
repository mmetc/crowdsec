// Code generated by ent, DO NOT EDIT.

package ent

import (
	"fmt"
	"strings"
	"time"

	"entgo.io/ent/dialect/sql"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/lock"
)

// Lock is the model entity for the Lock schema.
type Lock struct {
	config `json:"-"`
	// ID of the ent.
	ID int `json:"id,omitempty"`
	// Name holds the value of the "name" field.
	Name string `json:"name"`
	// CreatedAt holds the value of the "created_at" field.
	CreatedAt time.Time `json:"created_at"`
}

// scanValues returns the types for scanning values from sql.Rows.
func (*Lock) scanValues(columns []string) ([]any, error) {
	values := make([]any, len(columns))
	for i := range columns {
		switch columns[i] {
		case lock.FieldID:
			values[i] = new(sql.NullInt64)
		case lock.FieldName:
			values[i] = new(sql.NullString)
		case lock.FieldCreatedAt:
			values[i] = new(sql.NullTime)
		default:
			return nil, fmt.Errorf("unexpected column %q for type Lock", columns[i])
		}
	}
	return values, nil
}

// assignValues assigns the values that were returned from sql.Rows (after scanning)
// to the Lock fields.
func (l *Lock) assignValues(columns []string, values []any) error {
	if m, n := len(values), len(columns); m < n {
		return fmt.Errorf("mismatch number of scan values: %d != %d", m, n)
	}
	for i := range columns {
		switch columns[i] {
		case lock.FieldID:
			value, ok := values[i].(*sql.NullInt64)
			if !ok {
				return fmt.Errorf("unexpected type %T for field id", value)
			}
			l.ID = int(value.Int64)
		case lock.FieldName:
			if value, ok := values[i].(*sql.NullString); !ok {
				return fmt.Errorf("unexpected type %T for field name", values[i])
			} else if value.Valid {
				l.Name = value.String
			}
		case lock.FieldCreatedAt:
			if value, ok := values[i].(*sql.NullTime); !ok {
				return fmt.Errorf("unexpected type %T for field created_at", values[i])
			} else if value.Valid {
				l.CreatedAt = value.Time
			}
		}
	}
	return nil
}

// Update returns a builder for updating this Lock.
// Note that you need to call Lock.Unwrap() before calling this method if this Lock
// was returned from a transaction, and the transaction was committed or rolled back.
func (l *Lock) Update() *LockUpdateOne {
	return (&LockClient{config: l.config}).UpdateOne(l)
}

// Unwrap unwraps the Lock entity that was returned from a transaction after it was closed,
// so that all future queries will be executed through the driver which created the transaction.
func (l *Lock) Unwrap() *Lock {
	_tx, ok := l.config.driver.(*txDriver)
	if !ok {
		panic("ent: Lock is not a transactional entity")
	}
	l.config.driver = _tx.drv
	return l
}

// String implements the fmt.Stringer.
func (l *Lock) String() string {
	var builder strings.Builder
	builder.WriteString("Lock(")
	builder.WriteString(fmt.Sprintf("id=%v, ", l.ID))
	builder.WriteString("name=")
	builder.WriteString(l.Name)
	builder.WriteString(", ")
	builder.WriteString("created_at=")
	builder.WriteString(l.CreatedAt.Format(time.ANSIC))
	builder.WriteByte(')')
	return builder.String()
}

// Locks is a parsable slice of Lock.
type Locks []*Lock

func (l Locks) config(cfg config) {
	for _i := range l {
		l[_i].config = cfg
	}
}
