package driver

import (
	"context"
	"github.com/gobuffalo/pop/v6"
	"github.com/ory/x/networkx"
	redisClient "github.com/redis/go-redis/v9"

	"github.com/ory/hydra/v2/persistence/redis"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/luna-duclos/instrumentedsql"

	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/consent"
	"github.com/ory/hydra/v2/hsm"
	"github.com/ory/hydra/v2/jwk"
	"github.com/ory/hydra/v2/oauth2/trust"
	"github.com/ory/hydra/v2/persistence/sql"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/contextx"
	"github.com/ory/x/dbal"
	"github.com/ory/x/errorsx"
	otelsql "github.com/ory/x/otelx/sql"
	"github.com/ory/x/resilience"
	"github.com/ory/x/sqlcon"
)

type RegistryRedis struct {
	*RegistryBase
	defaultKeyManager jwk.Manager
	initialPing       func(r *RegistryRedis) error
	sqlPersister      *sql.Persister
}

func (m *RegistryRedis) CanHandle(dsn string) bool {
	scheme := strings.Split(dsn, "://")[0]
	return scheme == "redis"
}

var _ Registry = new(RegistryRedis)

// defaultRedisInitialPing is the default function that will be called within RegistryRedis.Init to make sure
// the database is reachable. It can be injected for test purposes by changing the value
// of RegistryRedis.initialPing.
var defaultRedisInitialPing = func(m *RegistryRedis) error {
	if err := resilience.Retry(m.l, 5*time.Second, 5*time.Minute, m.Ping); err != nil {
		m.Logger().Print("Could not ping database: ", err)
		return errorsx.WithStack(err)
	}
	return nil
}

func init() {
	dbal.RegisterDriver(
		func() dbal.Driver {
			return NewRegistryRedis()
		},
	)
}

func NewRegistryRedis() *RegistryRedis {
	r := &RegistryRedis{
		RegistryBase: new(RegistryBase),
		initialPing:  defaultRedisInitialPing,
	}
	r.RegistryBase.with(r)
	return r
}

func (m *RegistryRedis) Init(
	ctx context.Context, skipNetworkInit bool, migrate bool, ctxer contextx.Contextualizer,
) error {
	if m.persister == nil {
		m.WithContextualizer(ctxer)
		var opts []instrumentedsql.Opt
		if m.Tracer(ctx).IsLoaded() {
			opts = []instrumentedsql.Opt{
				instrumentedsql.WithTracer(otelsql.NewTracer()),
				instrumentedsql.WithOmitArgs(), // don't risk leaking PII or secrets
				instrumentedsql.WithOpsExcluded(instrumentedsql.OpSQLRowsNext),
			}
		}

		// all of the below is copied from reqistry_sql.go
		// we create a sql.Persister to fall through to for all the storage we haven't yet implemented in redis
		pool, idlePool, connMaxLifetime, connMaxIdleTime, cleanedDSN := sqlcon.ParseConnectionOptions(
			m.l,
			//m.Config().DSN(),
			os.Getenv("POSTGRES_DSN"),
		)
		c, err := pop.NewConnection(
			&pop.ConnectionDetails{
				URL:                       sqlcon.FinalizeDSN(m.l, cleanedDSN),
				IdlePool:                  idlePool,
				ConnMaxLifetime:           connMaxLifetime,
				ConnMaxIdleTime:           connMaxIdleTime,
				Pool:                      pool,
				UseInstrumentedDriver:     m.Tracer(ctx).IsLoaded(),
				InstrumentedDriverOptions: opts,
				Unsafe:                    m.Config().DbIgnoreUnknownTableColumns(),
			},
		)
		if err != nil {
			return errorsx.WithStack(err)
		}
		if err := resilience.Retry(m.l, 5*time.Second, 5*time.Minute, c.Open); err != nil {
			return errorsx.WithStack(err)
		}

		sqlPersister, err := sql.NewPersister(ctx, c, m, m.Config(), m.l)
		if err != nil {
			return err
		}

		var net *networkx.Network
		net, err = sqlPersister.DetermineNetwork(ctx)
		if err != nil {
			m.Logger().WithError(err).Warnf("Unable to determine network, retrying.")
			return err
		}

		sqlPersister = sqlPersister.WithFallbackNetworkIDSQL(net.ID)

		if m.Config().HSMEnabled() {
			hardwareKeyManager := hsm.NewKeyManager(m.HSMContext(), m.Config())
			m.defaultKeyManager = jwk.NewManagerStrategy(hardwareKeyManager, sqlPersister)
		} else {
			m.defaultKeyManager = sqlPersister
		}

		if migrate {
			if err := sqlPersister.MigrateUp(context.Background()); err != nil {
				return err
			}
		}

		redisURL := os.Getenv("DSN")
		ropts, err := redisClient.ParseClusterURL(redisURL)
		if err != nil {
			return err
		}
		rr := redisClient.NewClusterClient(ropts)
		rp := redis.NewPersister(ctx, rr, sqlPersister, m, m.Config(), m.l)
		if net != nil {
			rp = rp.WithFallbackNetworkID(net.ID)
		}
		m.persister = rp
		if err := m.initialPing(m); err != nil {
			return err
		}

	}

	return nil
}

func (m *RegistryRedis) Ping() error {
	return m.Persister().Ping()
}

func (m *RegistryRedis) ClientManager() client.Manager {
	return m.Persister()
}

func (m *RegistryRedis) ConsentManager() consent.Manager {
	return m.Persister()
}

func (m *RegistryRedis) OAuth2Storage() x.FositeStorer {
	return m.Persister()
}

func (m *RegistryRedis) KeyManager() jwk.Manager {
	return m.defaultKeyManager
}

func (m *RegistryRedis) SoftwareKeyManager() jwk.Manager {
	return m.Persister()
}

func (m *RegistryRedis) GrantManager() trust.GrantManager {
	return m.Persister()
}
