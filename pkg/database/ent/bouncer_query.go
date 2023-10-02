// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/bouncer"
	"github.com/crowdsecurity/crowdsec/pkg/database/ent/predicate"
)

// BouncerQuery is the builder for querying Bouncer entities.
type BouncerQuery struct {
	config
	limit      *int
	offset     *int
	unique     *bool
	order      []OrderFunc
	fields     []string
	predicates []predicate.Bouncer
	modifiers  []func(*sql.Selector)
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the BouncerQuery builder.
func (bq *BouncerQuery) Where(ps ...predicate.Bouncer) *BouncerQuery {
	bq.predicates = append(bq.predicates, ps...)
	return bq
}

// Limit adds a limit step to the query.
func (bq *BouncerQuery) Limit(limit int) *BouncerQuery {
	bq.limit = &limit
	return bq
}

// Offset adds an offset step to the query.
func (bq *BouncerQuery) Offset(offset int) *BouncerQuery {
	bq.offset = &offset
	return bq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (bq *BouncerQuery) Unique(unique bool) *BouncerQuery {
	bq.unique = &unique
	return bq
}

// Order adds an order step to the query.
func (bq *BouncerQuery) Order(o ...OrderFunc) *BouncerQuery {
	bq.order = append(bq.order, o...)
	return bq
}

// First returns the first Bouncer entity from the query.
// Returns a *NotFoundError when no Bouncer was found.
func (bq *BouncerQuery) First(ctx context.Context) (*Bouncer, error) {
	nodes, err := bq.Limit(1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{bouncer.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (bq *BouncerQuery) FirstX(ctx context.Context) *Bouncer {
	node, err := bq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first Bouncer ID from the query.
// Returns a *NotFoundError when no Bouncer ID was found.
func (bq *BouncerQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = bq.Limit(1).IDs(ctx); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{bouncer.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (bq *BouncerQuery) FirstIDX(ctx context.Context) int {
	id, err := bq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single Bouncer entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one Bouncer entity is found.
// Returns a *NotFoundError when no Bouncer entities are found.
func (bq *BouncerQuery) Only(ctx context.Context) (*Bouncer, error) {
	nodes, err := bq.Limit(2).All(ctx)
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{bouncer.Label}
	default:
		return nil, &NotSingularError{bouncer.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (bq *BouncerQuery) OnlyX(ctx context.Context) *Bouncer {
	node, err := bq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only Bouncer ID in the query.
// Returns a *NotSingularError when more than one Bouncer ID is found.
// Returns a *NotFoundError when no entities are found.
func (bq *BouncerQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = bq.Limit(2).IDs(ctx); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{bouncer.Label}
	default:
		err = &NotSingularError{bouncer.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (bq *BouncerQuery) OnlyIDX(ctx context.Context) int {
	id, err := bq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of Bouncers.
func (bq *BouncerQuery) All(ctx context.Context) ([]*Bouncer, error) {
	if err := bq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	return bq.sqlAll(ctx)
}

// AllX is like All, but panics if an error occurs.
func (bq *BouncerQuery) AllX(ctx context.Context) []*Bouncer {
	nodes, err := bq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of Bouncer IDs.
func (bq *BouncerQuery) IDs(ctx context.Context) ([]int, error) {
	var ids []int
	if err := bq.Select(bouncer.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (bq *BouncerQuery) IDsX(ctx context.Context) []int {
	ids, err := bq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (bq *BouncerQuery) Count(ctx context.Context) (int, error) {
	if err := bq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return bq.sqlCount(ctx)
}

// CountX is like Count, but panics if an error occurs.
func (bq *BouncerQuery) CountX(ctx context.Context) int {
	count, err := bq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (bq *BouncerQuery) Exist(ctx context.Context) (bool, error) {
	if err := bq.prepareQuery(ctx); err != nil {
		return false, err
	}
	return bq.sqlExist(ctx)
}

// ExistX is like Exist, but panics if an error occurs.
func (bq *BouncerQuery) ExistX(ctx context.Context) bool {
	exist, err := bq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the BouncerQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (bq *BouncerQuery) Clone() *BouncerQuery {
	if bq == nil {
		return nil
	}
	return &BouncerQuery{
		config:     bq.config,
		limit:      bq.limit,
		offset:     bq.offset,
		order:      append([]OrderFunc{}, bq.order...),
		predicates: append([]predicate.Bouncer{}, bq.predicates...),
		// clone intermediate query.
		sql:    bq.sql.Clone(),
		path:   bq.path,
		unique: bq.unique,
	}
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
//
// Example:
//
//	var v []struct {
//		CreatedAt time.Time `json:"created_at"`
//		Count int `json:"count,omitempty"`
//	}
//
//	client.Bouncer.Query().
//		GroupBy(bouncer.FieldCreatedAt).
//		Aggregate(ent.Count()).
//		Scan(ctx, &v)
func (bq *BouncerQuery) GroupBy(field string, fields ...string) *BouncerGroupBy {
	grbuild := &BouncerGroupBy{config: bq.config}
	grbuild.fields = append([]string{field}, fields...)
	grbuild.path = func(ctx context.Context) (prev *sql.Selector, err error) {
		if err := bq.prepareQuery(ctx); err != nil {
			return nil, err
		}
		return bq.sqlQuery(ctx), nil
	}
	grbuild.label = bouncer.Label
	grbuild.flds, grbuild.scan = &grbuild.fields, grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
//
// Example:
//
//	var v []struct {
//		CreatedAt time.Time `json:"created_at"`
//	}
//
//	client.Bouncer.Query().
//		Select(bouncer.FieldCreatedAt).
//		Scan(ctx, &v)
func (bq *BouncerQuery) Select(fields ...string) *BouncerSelect {
	bq.fields = append(bq.fields, fields...)
	selbuild := &BouncerSelect{BouncerQuery: bq}
	selbuild.label = bouncer.Label
	selbuild.flds, selbuild.scan = &bq.fields, selbuild.Scan
	return selbuild
}

func (bq *BouncerQuery) prepareQuery(ctx context.Context) error {
	for _, f := range bq.fields {
		if !bouncer.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if bq.path != nil {
		prev, err := bq.path(ctx)
		if err != nil {
			return err
		}
		bq.sql = prev
	}
	return nil
}

func (bq *BouncerQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*Bouncer, error) {
	var (
		nodes = []*Bouncer{}
		_spec = bq.querySpec()
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*Bouncer).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &Bouncer{config: bq.config}
		nodes = append(nodes, node)
		return node.assignValues(columns, values)
	}
	if len(bq.modifiers) > 0 {
		_spec.Modifiers = bq.modifiers
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, bq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	return nodes, nil
}

func (bq *BouncerQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := bq.querySpec()
	if len(bq.modifiers) > 0 {
		_spec.Modifiers = bq.modifiers
	}
	_spec.Node.Columns = bq.fields
	if len(bq.fields) > 0 {
		_spec.Unique = bq.unique != nil && *bq.unique
	}
	return sqlgraph.CountNodes(ctx, bq.driver, _spec)
}

func (bq *BouncerQuery) sqlExist(ctx context.Context) (bool, error) {
	switch _, err := bq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

func (bq *BouncerQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := &sqlgraph.QuerySpec{
		Node: &sqlgraph.NodeSpec{
			Table:   bouncer.Table,
			Columns: bouncer.Columns,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: bouncer.FieldID,
			},
		},
		From:   bq.sql,
		Unique: true,
	}
	if unique := bq.unique; unique != nil {
		_spec.Unique = *unique
	}
	if fields := bq.fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, bouncer.FieldID)
		for i := range fields {
			if fields[i] != bouncer.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := bq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := bq.limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := bq.offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := bq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (bq *BouncerQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(bq.driver.Dialect())
	t1 := builder.Table(bouncer.Table)
	columns := bq.fields
	if len(columns) == 0 {
		columns = bouncer.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if bq.sql != nil {
		selector = bq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if bq.unique != nil && *bq.unique {
		selector.Distinct()
	}
	for _, m := range bq.modifiers {
		m(selector)
	}
	for _, p := range bq.predicates {
		p(selector)
	}
	for _, p := range bq.order {
		p(selector)
	}
	if offset := bq.offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := bq.limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// ForUpdate locks the selected rows against concurrent updates, and prevent them from being
// updated, deleted or "selected ... for update" by other sessions, until the transaction is
// either committed or rolled-back.
func (bq *BouncerQuery) ForUpdate(opts ...sql.LockOption) *BouncerQuery {
	if bq.driver.Dialect() == dialect.Postgres {
		bq.Unique(false)
	}
	bq.modifiers = append(bq.modifiers, func(s *sql.Selector) {
		s.ForUpdate(opts...)
	})
	return bq
}

// ForShare behaves similarly to ForUpdate, except that it acquires a shared mode lock
// on any rows that are read. Other sessions can read the rows, but cannot modify them
// until your transaction commits.
func (bq *BouncerQuery) ForShare(opts ...sql.LockOption) *BouncerQuery {
	if bq.driver.Dialect() == dialect.Postgres {
		bq.Unique(false)
	}
	bq.modifiers = append(bq.modifiers, func(s *sql.Selector) {
		s.ForShare(opts...)
	})
	return bq
}

// BouncerGroupBy is the group-by builder for Bouncer entities.
type BouncerGroupBy struct {
	config
	selector
	fields []string
	fns    []AggregateFunc
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Aggregate adds the given aggregation functions to the group-by query.
func (bgb *BouncerGroupBy) Aggregate(fns ...AggregateFunc) *BouncerGroupBy {
	bgb.fns = append(bgb.fns, fns...)
	return bgb
}

// Scan applies the group-by query and scans the result into the given value.
func (bgb *BouncerGroupBy) Scan(ctx context.Context, v any) error {
	query, err := bgb.path(ctx)
	if err != nil {
		return err
	}
	bgb.sql = query
	return bgb.sqlScan(ctx, v)
}

func (bgb *BouncerGroupBy) sqlScan(ctx context.Context, v any) error {
	for _, f := range bgb.fields {
		if !bouncer.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("invalid field %q for group-by", f)}
		}
	}
	selector := bgb.sqlQuery()
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := bgb.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

func (bgb *BouncerGroupBy) sqlQuery() *sql.Selector {
	selector := bgb.sql.Select()
	aggregation := make([]string, 0, len(bgb.fns))
	for _, fn := range bgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	// If no columns were selected in a custom aggregation function, the default
	// selection is the fields used for "group-by", and the aggregation functions.
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(bgb.fields)+len(bgb.fns))
		for _, f := range bgb.fields {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	return selector.GroupBy(selector.Columns(bgb.fields...)...)
}

// BouncerSelect is the builder for selecting fields of Bouncer entities.
type BouncerSelect struct {
	*BouncerQuery
	selector
	// intermediate query (i.e. traversal path).
	sql *sql.Selector
}

// Scan applies the selector query and scans the result into the given value.
func (bs *BouncerSelect) Scan(ctx context.Context, v any) error {
	if err := bs.prepareQuery(ctx); err != nil {
		return err
	}
	bs.sql = bs.BouncerQuery.sqlQuery(ctx)
	return bs.sqlScan(ctx, v)
}

func (bs *BouncerSelect) sqlScan(ctx context.Context, v any) error {
	rows := &sql.Rows{}
	query, args := bs.sql.Query()
	if err := bs.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
