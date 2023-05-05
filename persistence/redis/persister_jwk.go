package redis

import (
	"context"
	"gopkg.in/square/go-jose.v2"
)

func (p Persister) GenerateAndPersistKeySet(ctx context.Context, set, kid, alg, use string) (*jose.JSONWebKeySet, error) {
	return p.sqlPersister.GenerateAndPersistKeySet(ctx, set, kid, alg, use)
}

func (p Persister) AddKey(ctx context.Context, set string, key *jose.JSONWebKey) error {
	return p.sqlPersister.AddKey(ctx, set, key)
}

func (p Persister) AddKeySet(ctx context.Context, set string, keys *jose.JSONWebKeySet) error {
	return p.sqlPersister.AddKeySet(ctx, set, keys)
}

func (p Persister) UpdateKey(ctx context.Context, set string, key *jose.JSONWebKey) error {
	return p.sqlPersister.UpdateKey(ctx, set, key)
}

func (p Persister) UpdateKeySet(ctx context.Context, set string, keys *jose.JSONWebKeySet) error {
	return p.sqlPersister.UpdateKeySet(ctx, set, keys)
}

func (p Persister) GetKey(ctx context.Context, set, kid string) (*jose.JSONWebKeySet, error) {
	return p.sqlPersister.GetKey(ctx, set, kid)
}

func (p Persister) GetKeySet(ctx context.Context, set string) (*jose.JSONWebKeySet, error) {
	return p.sqlPersister.GetKeySet(ctx, set)
}

func (p Persister) DeleteKey(ctx context.Context, set, kid string) error {
	return p.sqlPersister.DeleteKey(ctx, set, kid)
}

func (p Persister) DeleteKeySet(ctx context.Context, set string) error {
	return p.sqlPersister.DeleteKeySet(ctx, set)
}
