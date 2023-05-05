package redis

import (
	"context"
	"github.com/ory/x/popx"
)

func (p Persister) MigrationStatus(ctx context.Context) (popx.MigrationStatuses, error) {
	return p.sqlPersister.MigrationStatus(ctx)
}

func (p Persister) MigrateDown(ctx context.Context, i int) error {
	return p.sqlPersister.MigrateDown(ctx, i)
}

func (p Persister) MigrateUp(ctx context.Context) error {
	return p.sqlPersister.MigrateUp(ctx)
}

func (p Persister) PrepareMigration(ctx context.Context) error {
	return p.sqlPersister.PrepareMigration(ctx)
}
