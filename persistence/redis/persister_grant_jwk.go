package redis

import (
	"context"
	"github.com/ory/hydra/v2/oauth2/trust"
	"gopkg.in/square/go-jose.v2"
	"time"
)

func (p Persister) CreateGrant(ctx context.Context, g trust.Grant, publicKey jose.JSONWebKey) error {
	return p.sqlPersister.CreateGrant(ctx, g, publicKey)
}

func (p Persister) GetConcreteGrant(ctx context.Context, id string) (trust.Grant, error) {
	return p.sqlPersister.GetConcreteGrant(ctx, id)
}

func (p Persister) DeleteGrant(ctx context.Context, id string) error {
	return p.sqlPersister.DeleteGrant(ctx, id)
}

func (p Persister) GetGrants(ctx context.Context, limit, offset int, optionalIssuer string) ([]trust.Grant, error) {
	return p.sqlPersister.GetGrants(ctx, limit, offset, optionalIssuer)
}

func (p Persister) CountGrants(ctx context.Context) (int, error) {
	return p.sqlPersister.CountGrants(ctx)
}

func (p Persister) FlushInactiveGrants(ctx context.Context, notAfter time.Time, limit int, batchSize int) error {
	return p.sqlPersister.FlushInactiveGrants(ctx, notAfter, limit, batchSize)
}
func (p Persister) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	return p.sqlPersister.GetPublicKey(ctx, issuer, subject, keyId)
}

func (p Persister) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	return p.sqlPersister.GetPublicKeys(ctx, issuer, subject)
}

func (p Persister) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	return p.sqlPersister.GetPublicKeyScopes(ctx, issuer, subject, keyId)
}
