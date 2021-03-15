// Code generated by entc, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/alert"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/decision"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/event"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/machine"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/meta"
)

// AlertCreate is the builder for creating a Alert entity.
type AlertCreate struct {
	config
	mutation *AlertMutation
	hooks    []Hook
}

// SetCreatedAt sets the "created_at" field.
func (ac *AlertCreate) SetCreatedAt(t time.Time) *AlertCreate {
	ac.mutation.SetCreatedAt(t)
	return ac
}

// SetNillableCreatedAt sets the "created_at" field if the given value is not nil.
func (ac *AlertCreate) SetNillableCreatedAt(t *time.Time) *AlertCreate {
	if t != nil {
		ac.SetCreatedAt(*t)
	}
	return ac
}

// SetUpdatedAt sets the "updated_at" field.
func (ac *AlertCreate) SetUpdatedAt(t time.Time) *AlertCreate {
	ac.mutation.SetUpdatedAt(t)
	return ac
}

// SetNillableUpdatedAt sets the "updated_at" field if the given value is not nil.
func (ac *AlertCreate) SetNillableUpdatedAt(t *time.Time) *AlertCreate {
	if t != nil {
		ac.SetUpdatedAt(*t)
	}
	return ac
}

// SetScenario sets the "scenario" field.
func (ac *AlertCreate) SetScenario(s string) *AlertCreate {
	ac.mutation.SetScenario(s)
	return ac
}

// SetBucketId sets the "bucketId" field.
func (ac *AlertCreate) SetBucketId(s string) *AlertCreate {
	ac.mutation.SetBucketId(s)
	return ac
}

// SetNillableBucketId sets the "bucketId" field if the given value is not nil.
func (ac *AlertCreate) SetNillableBucketId(s *string) *AlertCreate {
	if s != nil {
		ac.SetBucketId(*s)
	}
	return ac
}

// SetMessage sets the "message" field.
func (ac *AlertCreate) SetMessage(s string) *AlertCreate {
	ac.mutation.SetMessage(s)
	return ac
}

// SetNillableMessage sets the "message" field if the given value is not nil.
func (ac *AlertCreate) SetNillableMessage(s *string) *AlertCreate {
	if s != nil {
		ac.SetMessage(*s)
	}
	return ac
}

// SetEventsCount sets the "eventsCount" field.
func (ac *AlertCreate) SetEventsCount(i int32) *AlertCreate {
	ac.mutation.SetEventsCount(i)
	return ac
}

// SetNillableEventsCount sets the "eventsCount" field if the given value is not nil.
func (ac *AlertCreate) SetNillableEventsCount(i *int32) *AlertCreate {
	if i != nil {
		ac.SetEventsCount(*i)
	}
	return ac
}

// SetStartedAt sets the "startedAt" field.
func (ac *AlertCreate) SetStartedAt(t time.Time) *AlertCreate {
	ac.mutation.SetStartedAt(t)
	return ac
}

// SetNillableStartedAt sets the "startedAt" field if the given value is not nil.
func (ac *AlertCreate) SetNillableStartedAt(t *time.Time) *AlertCreate {
	if t != nil {
		ac.SetStartedAt(*t)
	}
	return ac
}

// SetStoppedAt sets the "stoppedAt" field.
func (ac *AlertCreate) SetStoppedAt(t time.Time) *AlertCreate {
	ac.mutation.SetStoppedAt(t)
	return ac
}

// SetNillableStoppedAt sets the "stoppedAt" field if the given value is not nil.
func (ac *AlertCreate) SetNillableStoppedAt(t *time.Time) *AlertCreate {
	if t != nil {
		ac.SetStoppedAt(*t)
	}
	return ac
}

// SetSourceIp sets the "sourceIp" field.
func (ac *AlertCreate) SetSourceIp(s string) *AlertCreate {
	ac.mutation.SetSourceIp(s)
	return ac
}

// SetNillableSourceIp sets the "sourceIp" field if the given value is not nil.
func (ac *AlertCreate) SetNillableSourceIp(s *string) *AlertCreate {
	if s != nil {
		ac.SetSourceIp(*s)
	}
	return ac
}

// SetSourceRange sets the "sourceRange" field.
func (ac *AlertCreate) SetSourceRange(s string) *AlertCreate {
	ac.mutation.SetSourceRange(s)
	return ac
}

// SetNillableSourceRange sets the "sourceRange" field if the given value is not nil.
func (ac *AlertCreate) SetNillableSourceRange(s *string) *AlertCreate {
	if s != nil {
		ac.SetSourceRange(*s)
	}
	return ac
}

// SetSourceAsNumber sets the "sourceAsNumber" field.
func (ac *AlertCreate) SetSourceAsNumber(s string) *AlertCreate {
	ac.mutation.SetSourceAsNumber(s)
	return ac
}

// SetNillableSourceAsNumber sets the "sourceAsNumber" field if the given value is not nil.
func (ac *AlertCreate) SetNillableSourceAsNumber(s *string) *AlertCreate {
	if s != nil {
		ac.SetSourceAsNumber(*s)
	}
	return ac
}

// SetSourceAsName sets the "sourceAsName" field.
func (ac *AlertCreate) SetSourceAsName(s string) *AlertCreate {
	ac.mutation.SetSourceAsName(s)
	return ac
}

// SetNillableSourceAsName sets the "sourceAsName" field if the given value is not nil.
func (ac *AlertCreate) SetNillableSourceAsName(s *string) *AlertCreate {
	if s != nil {
		ac.SetSourceAsName(*s)
	}
	return ac
}

// SetSourceCountry sets the "sourceCountry" field.
func (ac *AlertCreate) SetSourceCountry(s string) *AlertCreate {
	ac.mutation.SetSourceCountry(s)
	return ac
}

// SetNillableSourceCountry sets the "sourceCountry" field if the given value is not nil.
func (ac *AlertCreate) SetNillableSourceCountry(s *string) *AlertCreate {
	if s != nil {
		ac.SetSourceCountry(*s)
	}
	return ac
}

// SetSourceLatitude sets the "sourceLatitude" field.
func (ac *AlertCreate) SetSourceLatitude(f float32) *AlertCreate {
	ac.mutation.SetSourceLatitude(f)
	return ac
}

// SetNillableSourceLatitude sets the "sourceLatitude" field if the given value is not nil.
func (ac *AlertCreate) SetNillableSourceLatitude(f *float32) *AlertCreate {
	if f != nil {
		ac.SetSourceLatitude(*f)
	}
	return ac
}

// SetSourceLongitude sets the "sourceLongitude" field.
func (ac *AlertCreate) SetSourceLongitude(f float32) *AlertCreate {
	ac.mutation.SetSourceLongitude(f)
	return ac
}

// SetNillableSourceLongitude sets the "sourceLongitude" field if the given value is not nil.
func (ac *AlertCreate) SetNillableSourceLongitude(f *float32) *AlertCreate {
	if f != nil {
		ac.SetSourceLongitude(*f)
	}
	return ac
}

// SetSourceScope sets the "sourceScope" field.
func (ac *AlertCreate) SetSourceScope(s string) *AlertCreate {
	ac.mutation.SetSourceScope(s)
	return ac
}

// SetNillableSourceScope sets the "sourceScope" field if the given value is not nil.
func (ac *AlertCreate) SetNillableSourceScope(s *string) *AlertCreate {
	if s != nil {
		ac.SetSourceScope(*s)
	}
	return ac
}

// SetSourceValue sets the "sourceValue" field.
func (ac *AlertCreate) SetSourceValue(s string) *AlertCreate {
	ac.mutation.SetSourceValue(s)
	return ac
}

// SetNillableSourceValue sets the "sourceValue" field if the given value is not nil.
func (ac *AlertCreate) SetNillableSourceValue(s *string) *AlertCreate {
	if s != nil {
		ac.SetSourceValue(*s)
	}
	return ac
}

// SetCapacity sets the "capacity" field.
func (ac *AlertCreate) SetCapacity(i int32) *AlertCreate {
	ac.mutation.SetCapacity(i)
	return ac
}

// SetNillableCapacity sets the "capacity" field if the given value is not nil.
func (ac *AlertCreate) SetNillableCapacity(i *int32) *AlertCreate {
	if i != nil {
		ac.SetCapacity(*i)
	}
	return ac
}

// SetLeakSpeed sets the "leakSpeed" field.
func (ac *AlertCreate) SetLeakSpeed(s string) *AlertCreate {
	ac.mutation.SetLeakSpeed(s)
	return ac
}

// SetNillableLeakSpeed sets the "leakSpeed" field if the given value is not nil.
func (ac *AlertCreate) SetNillableLeakSpeed(s *string) *AlertCreate {
	if s != nil {
		ac.SetLeakSpeed(*s)
	}
	return ac
}

// SetScenarioVersion sets the "scenarioVersion" field.
func (ac *AlertCreate) SetScenarioVersion(s string) *AlertCreate {
	ac.mutation.SetScenarioVersion(s)
	return ac
}

// SetNillableScenarioVersion sets the "scenarioVersion" field if the given value is not nil.
func (ac *AlertCreate) SetNillableScenarioVersion(s *string) *AlertCreate {
	if s != nil {
		ac.SetScenarioVersion(*s)
	}
	return ac
}

// SetScenarioHash sets the "scenarioHash" field.
func (ac *AlertCreate) SetScenarioHash(s string) *AlertCreate {
	ac.mutation.SetScenarioHash(s)
	return ac
}

// SetNillableScenarioHash sets the "scenarioHash" field if the given value is not nil.
func (ac *AlertCreate) SetNillableScenarioHash(s *string) *AlertCreate {
	if s != nil {
		ac.SetScenarioHash(*s)
	}
	return ac
}

// SetSimulated sets the "simulated" field.
func (ac *AlertCreate) SetSimulated(b bool) *AlertCreate {
	ac.mutation.SetSimulated(b)
	return ac
}

// SetNillableSimulated sets the "simulated" field if the given value is not nil.
func (ac *AlertCreate) SetNillableSimulated(b *bool) *AlertCreate {
	if b != nil {
		ac.SetSimulated(*b)
	}
	return ac
}

// SetOwnerID sets the "owner" edge to the Machine entity by ID.
func (ac *AlertCreate) SetOwnerID(id int) *AlertCreate {
	ac.mutation.SetOwnerID(id)
	return ac
}

// SetNillableOwnerID sets the "owner" edge to the Machine entity by ID if the given value is not nil.
func (ac *AlertCreate) SetNillableOwnerID(id *int) *AlertCreate {
	if id != nil {
		ac = ac.SetOwnerID(*id)
	}
	return ac
}

// SetOwner sets the "owner" edge to the Machine entity.
func (ac *AlertCreate) SetOwner(m *Machine) *AlertCreate {
	return ac.SetOwnerID(m.ID)
}

// AddDecisionIDs adds the "decisions" edge to the Decision entity by IDs.
func (ac *AlertCreate) AddDecisionIDs(ids ...int) *AlertCreate {
	ac.mutation.AddDecisionIDs(ids...)
	return ac
}

// AddDecisions adds the "decisions" edges to the Decision entity.
func (ac *AlertCreate) AddDecisions(d ...*Decision) *AlertCreate {
	ids := make([]int, len(d))
	for i := range d {
		ids[i] = d[i].ID
	}
	return ac.AddDecisionIDs(ids...)
}

// AddEventIDs adds the "events" edge to the Event entity by IDs.
func (ac *AlertCreate) AddEventIDs(ids ...int) *AlertCreate {
	ac.mutation.AddEventIDs(ids...)
	return ac
}

// AddEvents adds the "events" edges to the Event entity.
func (ac *AlertCreate) AddEvents(e ...*Event) *AlertCreate {
	ids := make([]int, len(e))
	for i := range e {
		ids[i] = e[i].ID
	}
	return ac.AddEventIDs(ids...)
}

// AddMetaIDs adds the "metas" edge to the Meta entity by IDs.
func (ac *AlertCreate) AddMetaIDs(ids ...int) *AlertCreate {
	ac.mutation.AddMetaIDs(ids...)
	return ac
}

// AddMetas adds the "metas" edges to the Meta entity.
func (ac *AlertCreate) AddMetas(m ...*Meta) *AlertCreate {
	ids := make([]int, len(m))
	for i := range m {
		ids[i] = m[i].ID
	}
	return ac.AddMetaIDs(ids...)
}

// Mutation returns the AlertMutation object of the builder.
func (ac *AlertCreate) Mutation() *AlertMutation {
	return ac.mutation
}

// Save creates the Alert in the database.
func (ac *AlertCreate) Save(ctx context.Context) (*Alert, error) {
	var (
		err  error
		node *Alert
	)
	ac.defaults()
	if len(ac.hooks) == 0 {
		if err = ac.check(); err != nil {
			return nil, err
		}
		node, err = ac.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*AlertMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = ac.check(); err != nil {
				return nil, err
			}
			ac.mutation = mutation
			node, err = ac.sqlSave(ctx)
			mutation.done = true
			return node, err
		})
		for i := len(ac.hooks) - 1; i >= 0; i-- {
			mut = ac.hooks[i](mut)
		}
		if _, err := mut.Mutate(ctx, ac.mutation); err != nil {
			return nil, err
		}
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (ac *AlertCreate) SaveX(ctx context.Context) *Alert {
	v, err := ac.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// defaults sets the default values of the builder before save.
func (ac *AlertCreate) defaults() {
	if _, ok := ac.mutation.CreatedAt(); !ok {
		v := alert.DefaultCreatedAt()
		ac.mutation.SetCreatedAt(v)
	}
	if _, ok := ac.mutation.UpdatedAt(); !ok {
		v := alert.DefaultUpdatedAt()
		ac.mutation.SetUpdatedAt(v)
	}
	if _, ok := ac.mutation.BucketId(); !ok {
		v := alert.DefaultBucketId
		ac.mutation.SetBucketId(v)
	}
	if _, ok := ac.mutation.Message(); !ok {
		v := alert.DefaultMessage
		ac.mutation.SetMessage(v)
	}
	if _, ok := ac.mutation.EventsCount(); !ok {
		v := alert.DefaultEventsCount
		ac.mutation.SetEventsCount(v)
	}
	if _, ok := ac.mutation.StartedAt(); !ok {
		v := alert.DefaultStartedAt()
		ac.mutation.SetStartedAt(v)
	}
	if _, ok := ac.mutation.StoppedAt(); !ok {
		v := alert.DefaultStoppedAt()
		ac.mutation.SetStoppedAt(v)
	}
	if _, ok := ac.mutation.Simulated(); !ok {
		v := alert.DefaultSimulated
		ac.mutation.SetSimulated(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (ac *AlertCreate) check() error {
	if _, ok := ac.mutation.CreatedAt(); !ok {
		return &ValidationError{Name: "created_at", err: errors.New("ent: missing required field \"created_at\"")}
	}
	if _, ok := ac.mutation.UpdatedAt(); !ok {
		return &ValidationError{Name: "updated_at", err: errors.New("ent: missing required field \"updated_at\"")}
	}
	if _, ok := ac.mutation.Scenario(); !ok {
		return &ValidationError{Name: "scenario", err: errors.New("ent: missing required field \"scenario\"")}
	}
	if _, ok := ac.mutation.Simulated(); !ok {
		return &ValidationError{Name: "simulated", err: errors.New("ent: missing required field \"simulated\"")}
	}
	return nil
}

func (ac *AlertCreate) sqlSave(ctx context.Context) (*Alert, error) {
	_node, _spec := ac.createSpec()
	if err := sqlgraph.CreateNode(ctx, ac.driver, _spec); err != nil {
		if cerr, ok := isSQLConstraintError(err); ok {
			err = cerr
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	return _node, nil
}

func (ac *AlertCreate) createSpec() (*Alert, *sqlgraph.CreateSpec) {
	var (
		_node = &Alert{config: ac.config}
		_spec = &sqlgraph.CreateSpec{
			Table: alert.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: alert.FieldID,
			},
		}
	)
	if value, ok := ac.mutation.CreatedAt(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: alert.FieldCreatedAt,
		})
		_node.CreatedAt = value
	}
	if value, ok := ac.mutation.UpdatedAt(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: alert.FieldUpdatedAt,
		})
		_node.UpdatedAt = value
	}
	if value, ok := ac.mutation.Scenario(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldScenario,
		})
		_node.Scenario = value
	}
	if value, ok := ac.mutation.BucketId(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldBucketId,
		})
		_node.BucketId = value
	}
	if value, ok := ac.mutation.Message(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldMessage,
		})
		_node.Message = value
	}
	if value, ok := ac.mutation.EventsCount(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeInt32,
			Value:  value,
			Column: alert.FieldEventsCount,
		})
		_node.EventsCount = value
	}
	if value, ok := ac.mutation.StartedAt(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: alert.FieldStartedAt,
		})
		_node.StartedAt = value
	}
	if value, ok := ac.mutation.StoppedAt(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeTime,
			Value:  value,
			Column: alert.FieldStoppedAt,
		})
		_node.StoppedAt = value
	}
	if value, ok := ac.mutation.SourceIp(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldSourceIp,
		})
		_node.SourceIp = value
	}
	if value, ok := ac.mutation.SourceRange(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldSourceRange,
		})
		_node.SourceRange = value
	}
	if value, ok := ac.mutation.SourceAsNumber(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldSourceAsNumber,
		})
		_node.SourceAsNumber = value
	}
	if value, ok := ac.mutation.SourceAsName(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldSourceAsName,
		})
		_node.SourceAsName = value
	}
	if value, ok := ac.mutation.SourceCountry(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldSourceCountry,
		})
		_node.SourceCountry = value
	}
	if value, ok := ac.mutation.SourceLatitude(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeFloat32,
			Value:  value,
			Column: alert.FieldSourceLatitude,
		})
		_node.SourceLatitude = value
	}
	if value, ok := ac.mutation.SourceLongitude(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeFloat32,
			Value:  value,
			Column: alert.FieldSourceLongitude,
		})
		_node.SourceLongitude = value
	}
	if value, ok := ac.mutation.SourceScope(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldSourceScope,
		})
		_node.SourceScope = value
	}
	if value, ok := ac.mutation.SourceValue(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldSourceValue,
		})
		_node.SourceValue = value
	}
	if value, ok := ac.mutation.Capacity(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeInt32,
			Value:  value,
			Column: alert.FieldCapacity,
		})
		_node.Capacity = value
	}
	if value, ok := ac.mutation.LeakSpeed(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldLeakSpeed,
		})
		_node.LeakSpeed = value
	}
	if value, ok := ac.mutation.ScenarioVersion(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldScenarioVersion,
		})
		_node.ScenarioVersion = value
	}
	if value, ok := ac.mutation.ScenarioHash(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: alert.FieldScenarioHash,
		})
		_node.ScenarioHash = value
	}
	if value, ok := ac.mutation.Simulated(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeBool,
			Value:  value,
			Column: alert.FieldSimulated,
		})
		_node.Simulated = value
	}
	if nodes := ac.mutation.OwnerIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   alert.OwnerTable,
			Columns: []string{alert.OwnerColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: machine.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.machine_alerts = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ac.mutation.DecisionsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   alert.DecisionsTable,
			Columns: []string{alert.DecisionsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: decision.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ac.mutation.EventsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   alert.EventsTable,
			Columns: []string{alert.EventsColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: event.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := ac.mutation.MetasIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.O2M,
			Inverse: false,
			Table:   alert.MetasTable,
			Columns: []string{alert.MetasColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: &sqlgraph.FieldSpec{
					Type:   field.TypeInt,
					Column: meta.FieldID,
				},
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// AlertCreateBulk is the builder for creating many Alert entities in bulk.
type AlertCreateBulk struct {
	config
	builders []*AlertCreate
}

// Save creates the Alert entities in the database.
func (acb *AlertCreateBulk) Save(ctx context.Context) ([]*Alert, error) {
	specs := make([]*sqlgraph.CreateSpec, len(acb.builders))
	nodes := make([]*Alert, len(acb.builders))
	mutators := make([]Mutator, len(acb.builders))
	for i := range acb.builders {
		func(i int, root context.Context) {
			builder := acb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*AlertMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				nodes[i], specs[i] = builder.createSpec()
				var err error
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, acb.builders[i+1].mutation)
				} else {
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, acb.driver, &sqlgraph.BatchCreateSpec{Nodes: specs}); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, acb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (acb *AlertCreateBulk) SaveX(ctx context.Context) []*Alert {
	v, err := acb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}
