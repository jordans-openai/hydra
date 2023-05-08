package redis

import (
	"context"
	"github.com/ory/fosite"
	"github.com/ory/hydra/v2/client"
	"time"
)

func (p Persister) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	return p.sqlPersister.GetClient(ctx, id)
}

func (p Persister) CreateClient(ctx context.Context, c *client.Client) error {
	return p.sqlPersister.CreateClient(ctx, c)
}

func (p Persister) UpdateClient(ctx context.Context, c *client.Client) error {
	return p.sqlPersister.UpdateClient(ctx, c)
}

func (p Persister) DeleteClient(ctx context.Context, id string) error {
	return p.sqlPersister.DeleteClient(ctx, id)
}

func (p Persister) GetClients(ctx context.Context, filters client.Filter) ([]client.Client, error) {
	return p.sqlPersister.GetClients(ctx, filters)
}

func (p Persister) CountClients(ctx context.Context) (int, error) {
	return p.sqlPersister.CountClients(ctx)
}

func (p Persister) GetConcreteClient(ctx context.Context, id string) (*client.Client, error) {
	cl, found := p.cache.Get(id)
	if found {
		return cl.(*client.Client), nil
	}

	cl, err := p.sqlPersister.GetConcreteClient(ctx, id)
	if err != nil {
		return nil, err
	}

	p.cache.Set(id, cl, 1*time.Minute)

	return cl.(*client.Client), nil
}

func (p Persister) Authenticate(ctx context.Context, id string, secret []byte) (*client.Client, error) {
	return p.sqlPersister.Authenticate(ctx, id, secret)
}
