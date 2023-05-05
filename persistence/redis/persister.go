package redis

import (
	"context"
	"github.com/ory/hydra/v2/persistence/sql"
	"github.com/redis/go-redis/v9"
	"strings"
	"time"

	"github.com/gobuffalo/pop/v6"
	"github.com/gofrs/uuid"

	"github.com/ory/fosite"
	"github.com/ory/hydra/v2/driver/config"
	"github.com/ory/hydra/v2/jwk"
	"github.com/ory/hydra/v2/persistence"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/contextx"
	"github.com/ory/x/logrusx"
)

var _ persistence.Persister = new(Persister)
var lifespan = time.Hour

type (
	Persister struct {
		r            Dependencies
		config       *config.DefaultProvider
		l            *logrusx.Logger
		fallbackNID  uuid.UUID
		DB           redis.UniversalClient
		KeyPrefix    string
		sqlPersister *sql.Persister
	}
	Dependencies interface {
		ClientHasher() fosite.Hasher
		KeyCipher() *jwk.AEAD
		contextx.Provider
		x.RegistryLogger
		x.TracingProvider
	}
)

const (
	prefixOIDC    = "oidc"
	prefixAccess  = "accs"
	prefixRefresh = "refr"
	prefixCode    = "code"
	prefixPKCE    = "pkce"
	setFragment   = "s"
	clientShards  = 128
)

func NewPersister(_ context.Context, r redis.UniversalClient, sqlPersister *sql.Persister, d Dependencies, config *config.DefaultProvider, l *logrusx.Logger) *Persister {
	return &Persister{
		DB:           r,
		r:            d,
		config:       config,
		l:            l,
		KeyPrefix:    "hydra:oauth2:",
		sqlPersister: sqlPersister,
	}
}

//func (p *Persister) DetermineNetwork(ctx context.Context) (*networkx.Network, error) {
//	return p.p.Determine(ctx)
//}

func (p Persister) WithFallbackNetworkID(nid uuid.UUID) *Persister {
	p.fallbackNID = nid
	return &p
}

//func (p Persister) WithFallbackNetworkIDSQL(nid uuid.UUID) *Persister {
//	p.fallbackNID = nid
//	return &p
//}

//func (p *Persister) CreateWithNetwork(ctx context.Context, v interface{}) error {
//	n := p.NetworkID(ctx)
//	return p.Connection(ctx).Create(p.mustSetNetwork(n, v))
//}

//func (p *Persister) UpdateWithNetwork(ctx context.Context, v interface{}) (int64, error) {
//	n := p.NetworkID(ctx)
//	v = p.mustSetNetwork(n, v)
//
//	m := pop.NewModel(v, ctx)
//	var cs []string
//	for _, t := range m.Columns().Cols {
//		cs = append(cs, t.Name)
//	}
//
//	return p.Connection(ctx).Where(m.IDField()+" = ? AND nid = ?", m.ID(), n).UpdateQuery(v, cs...)
//}

//func (p *Persister) NetworkID(ctx context.Context) uuid.UUID {
//	return p.r.Contextualizer().Network(ctx, p.fallbackNID)
//}

//func (p *Persister) QueryWithNetwork(ctx context.Context) *pop.Query {
//	return p.Connection(ctx).Where("nid = ?", p.NetworkID(ctx))
//}

func (p *Persister) Connection(ctx context.Context) *pop.Connection {
	return nil
}

func (p *Persister) Ping() error {
	_, err := p.DB.Ping(context.Background()).Result()
	return err
}

func (p Persister) redisKey(fields ...string) string {
	return p.KeyPrefix + strings.Join(fields, ":")
}
