// Code generated by entc, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/meta"
	"github.com/facebook/ent/dialect/sql/sqlgraph"
	"github.com/facebook/ent/schema/field"
)

// MetaCreate is the builder for creating a Meta entity.
type MetaCreate struct {
	config
	mutation *MetaMutation
	hooks    []Hook
}

// SetCreatedAt sets the created_at field.
func (mc *MetaCreate) SetCreatedAt(t time.Time) *MetaCreate {
	mc.mutation.SetCreatedAt(t)
	return mc
}

// SetNillableCreatedAt sets the created_at field if the given value is not nil.
func (mc *MetaCreate) SetNillableCreatedAt(t *time.Time) *MetaCreate {
	if t != nil {
		mc.SetCreatedAt(*t)
	}
	return mc
}

// SetUpdatedAt sets the updated_at field.
func (mc *MetaCreate) SetUpdatedAt(t time.Time) *MetaCreate {
	mc.mutation.SetUpdatedAt(t)
	return mc
}

// SetNillableUpdatedAt sets the updated_at field if the given value is not nil.
func (mc *MetaCreate) SetNillableUpdatedAt(t *time.Time) *MetaCreate {
	if t != nil {
		mc.SetUpdatedAt(*t)
	}
	return mc
}

// SetKey sets the key field.
func (mc *MetaCreate) SetKey(s string) *MetaCreate {
	mc.mutation.SetKey(s)
	return mc
}

// SetValue sets the value field.
func (mc *MetaCreate) SetValue(s string) *MetaCreate {
	mc.mutation.SetValue(s)
	return mc
}

// SetOwnerID sets the owner edge to Alert by id.
func (mc *MetaCreate) SetOwnerID(id int) *MetaCreate {
	mc.mutation.SetOwnerID(id)
	return mc
}

// SetNillableOwnerID sets the owner edge to Alert by id if the given value is not nil.
func (mc *MetaCreate) SetNillableOwnerID(id *int) *MetaCreate {
	if id != nil {
		mc = mc.SetOwnerID(*id)
	}
	return mc
}

// SetOwner sets the owner edge to Alert.
func (mc *MetaCreate) SetOwner(a *Alert) *MetaCreate {
	return mc.SetOwnerID(a.ID)
}

// Mutation returns the MetaMutation object of the builder.
func (mc *MetaCreate) Mutation() *MetaMutation {
	return mc.mutation
}

// Save creates the Meta in the database.
func (mc *MetaCreate) Save(ctx context.Context) (*Meta, error) {
	if err := mc.preSave(); err != nil {
		return nil, err
	}
	var (
		err  error
		node *Meta
	)
	if len(mc.hooks) == 0 {
		node, err = mc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*MetaMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			mc.mutation = mutation
			node, err = mc.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(mc.hooks) - 1; i >= 0; i-- {
			mut = mc.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, mc.mutation); err != nil {
			return nil, err
		}
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (mc *MetaCreate) SaveX(ctx context.Context) *Meta {
	v, err := mc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

func (mc *MetaCreate) preSave() error {
	if _, ok := mc.mutation.CreatedAt(); !ok {
		v := meta.DefaultCreatedAt()
		mc.mutation.SetCreatedAt(v)
	}
	if _, ok := mc.mutation.UpdatedAt(); !ok {
		v := meta.DefaultUpdatedAt()
		mc.mutation.SetUpdatedAt(v)
	}
	if _, ok := mc.mutation.Key(); !ok {
		return &ValidationError{Name: "key", err: errors.New("ent: missing required field \"key\"")}
	}
	if _, ok := mc.mutation.Value(); !ok {
		return &ValidationError{Name: "value", err: errors.New("ent: missing required field \"value\"")}
	}
	return nil
}

func (mc *MetaCreate) sqlSave(ctx context.Context) (*Meta, error) {
	m, _spec := mc.createSpec()
	if err := sqlgraph.CreateNode(ctx, mc.driver, _spec); err != nil {
		if cerr, ok := isSQLConstraintError(err); ok {
			err = cerr
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	m.ID = int(id)
	return m, nil
}

func (mc *MetaCreate) createSpec() (*Meta, *sqlgraph.CreateSpec) {
	var (
		m     = &Meta{config: mc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: meta.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: meta.FieldID,
			},
		}
	)
	if value, ok := mc.mutation.CreatedAt(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: meta.FieldCreatedAt,
		})
		m.CreatedAt = value
	}
	if value, ok := mc.mutation.UpdatedAt(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: meta.FieldUpdatedAt,
		})
		m.UpdatedAt = value
	}
	if value, ok := mc.mutation.Key(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: meta.FieldKey,
		})
		m.Key = value
	}
	if value, ok := mc.mutation.Value(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: meta.FieldValue,
		})
		m.Value = value
	}
	if nodes := mc.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   meta.OwnerTable,
			Columns: []string{meta.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: alert.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return m, _spec
}

// MetaCreateBulk is the builder for creating a bulk of Meta entities.
type MetaCreateBulk struct {
	config
	builders []*MetaCreate
}

// Save creates the Meta entities in the database.
func (mcb *MetaCreateBulk) Save(ctx context.Context) ([]*Meta, error) {
	specs := make([]*sqlgraph.CreateSpec, len(mcb.builders))
	nodes := make([]*Meta, len(mcb.builders))
	mutators := make([]Mutator, len(mcb.builders))
	for i := range mcb.builders {
		func(i int, root context.Context) {
			builder := mcb.builders[i]
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				if err := builder.preSave(); err != nil {
					return nil, err
				}
				mutation, ok := m.(*MetaMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				builder.mutation = mutation
				nodes[i], specs[i] = builder.createSpec()
				var err error
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, mcb.builders[i+1].mutation)
				} else {
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, mcb.driver, &sqlgraph.BatchCreateSpec{Nodes: specs}); err != nil {
						if cerr, ok := isSQLConstraintError(err); ok {
							err = cerr
						}
					}
				}
				mutation.done = true
				if err != nil {
					return nil, err
				}
				id := specs[i].ID.Value.(int64)
				nodes[i].ID = int(id)
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, mcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX calls Save and panics if Save returns an error.
func (mcb *MetaCreateBulk) SaveX(ctx context.Context) []*Meta {
	v, err := mcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}
