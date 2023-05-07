package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ory/fosite"
	"github.com/ory/hydra/v2/client"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"golang.org/x/text/language"
	"net/url"
	"strings"
	"time"
)

type redisSchema struct {
	ID                string           `json:"id"`
	RequestedAt       time.Time        `json:"requestedAt"`
	Client            *client.Client   `json:"client"`
	RequestedScope    fosite.Arguments `json:"scopes"`
	GrantedScope      fosite.Arguments `json:"grantedScopes"`
	Form              url.Values       `json:"form"`
	Session           json.RawMessage  `json:"session"`
	RequestedAudience fosite.Arguments `json:"requestedAudience"`
	GrantedAudience   fosite.Arguments `json:"grantedAudience"`
	Lang              language.Tag     `json:"-"`

	// extra fields
	Inactive bool `json:"inactive"`
}

func (p Persister) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.CreateOpenIDConnectSession")
	defer span.End()
	return p.setRequest(ctx, p.redisKey(prefixOIDC, authorizeCode), req)
}

func (p Persister) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) (fosite.Requester, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.GetOpenIDConnectSession")
	defer span.End()
	r, _, err := p.getRequest(ctx, p.redisKey(prefixOIDC, authorizeCode), req.GetSession())
	if err == redis.Nil {
		return nil, fosite.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "storage error")
	}

	return r, nil
}

func (p Persister) GetAuthorizeCodeSession(ctx context.Context, code string, sess fosite.Session) (fosite.Requester, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.GetAuthorizeCodeSession")
	defer span.End()
	req, inactive, err := p.getRequest(ctx, p.redisKey(prefixCode, code), sess)
	if err == redis.Nil {
		return nil, fosite.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "storage error")
	} else if inactive {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}

	return req, nil
}

func (p Persister) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.InvalidateAuthorizeCodeSession")
	defer span.End()
	return p.deactivate(ctx, p.redisKey(prefixCode, code))
}

func (p Persister) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.GetPKCERequestSession")
	defer span.End()
	req, _, err := p.getRequest(ctx, p.redisKey(prefixPKCE, signature), session)
	if err == redis.Nil {
		return nil, fosite.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "storage error")
	}
	return req, nil
}

func (p Persister) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.CreatePKCERequestSession")
	defer span.End()
	return p.setRequest(ctx, p.redisKey(prefixPKCE, signature), requester)
}

func (p Persister) DeletePKCERequestSession(ctx context.Context, signature string) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.DeletePKCERequestSession")
	defer span.End()
	return p.deleteRequest(ctx, prefixPKCE, signature)
}

func (p Persister) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.CreateAccessTokenSession")
	defer span.End()
	return p.redisCreateTokenSession(
		ctx,
		req,
		p.redisKey(prefixAccess, signature),
		p.redisKey(prefixAccess, setFragment, req.GetID()),
		signature,
	)
}

func (p Persister) GetAccessTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.GetAccessTokenSession")
	defer span.End()
	req, _, err := p.getRequest(ctx, p.redisKey(prefixAccess, signature), sess)
	if err == redis.Nil {
		return nil, fosite.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "storage error")
	}

	return req, nil
}

func (p Persister) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.DeleteAccessTokenSession")
	defer span.End()
	return p.deleteRequest(ctx, prefixAccess, signature)
}

func (p Persister) CreateRefreshTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.CreateRefreshTokenSession")
	defer span.End()
	return p.redisCreateTokenSession(
		ctx,
		req,
		p.redisKey(prefixRefresh, signature),
		p.redisKey(prefixRefresh, setFragment, req.GetID()),
		signature,
	)
}

func (p Persister) GetRefreshTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.GetRefreshTokenSession")
	defer span.End()
	session, inactive, err := p.getRequest(ctx, p.redisKey(prefixRefresh, signature), sess)
	if err == redis.Nil {
		return nil, fosite.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "storage error")
	} else if inactive {
		return session, fosite.ErrInactiveToken
	}
	return session, nil
}

func (p Persister) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.DeleteRefreshTokenSession")
	defer span.End()
	return p.deleteRequest(ctx, prefixRefresh, signature)
}

func (p Persister) CreateImplicitAccessTokenSession(ctx context.Context, code string, req fosite.Requester) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.CreateImplicitAccessTokenSession")
	defer span.End()
	return p.CreateAccessTokenSession(ctx, code, req)
}

func (p Persister) PersistAuthorizeCodeGrantSession(ctx context.Context, authorizeCode, accessSignature, refreshSignature string, req fosite.Requester) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.PersistAuthorizeCodeGrantSession")
	defer span.End()
	if err := p.DB.Del(ctx, p.redisKey(prefixCode, authorizeCode)).Err(); err != nil {
		return err
	} else if err = p.CreateAccessTokenSession(ctx, accessSignature, req); err != nil {
		return err
	}
	if refreshSignature == "" {
		return nil
	}
	if err := p.CreateRefreshTokenSession(ctx, refreshSignature, req); err != nil {
		return err
	}
	return nil
}

func (p Persister) PersistRefreshTokenGrantSession(ctx context.Context, originalRefreshSignature, accessSignature, refreshSignature string, req fosite.Requester) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.PersistentRefreshTokenGrantSession")
	defer span.End()
	if err := p.DeleteRefreshTokenSession(ctx, originalRefreshSignature); err != nil {
		return err
	} else if err = p.CreateAccessTokenSession(ctx, accessSignature, req); err != nil {
		return err
	} else if err = p.CreateRefreshTokenSession(ctx, refreshSignature, req); err != nil {
		return err
	}
	return nil
}

func (p Persister) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.DeleteOpenIDConnectSession")
	defer span.End()
	return p.DB.Del(ctx, p.redisKey(prefixOIDC, authorizeCode)).Err()
}

func (p Persister) RevokeRefreshToken(ctx context.Context, id string) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.RevokeRefreshToken")
	defer span.End()
	refreshSet := p.redisKey(prefixRefresh, setFragment, id)
	iter := p.DB.SScan(ctx, refreshSet, 0, "", 500).Iterator()
	sigs := make([]interface{}, 0)
	refreshKeys := make([]string, 0)
	for iter.Next(ctx) {
		sig := iter.Val()
		sigs = append(sigs, sig)
		refreshKeys = append(refreshKeys, p.redisKey(prefixRefresh, sig))
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range refreshKeys {
		if err := p.deactivate(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

func (p *Persister) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, id string, _ string) error {
	return p.RevokeRefreshToken(ctx, id)
}

func (p Persister) RevokeAccessToken(ctx context.Context, id string) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.RevokeAccessToken")
	defer span.End()
	accessSet := p.redisKey(prefixAccess, setFragment, id)
	iter := p.DB.SScan(ctx, accessSet, 0, "", 500).Iterator()
	sigs := make([]interface{}, 0)
	accessKeys := make([]string, 0)
	for iter.Next(ctx) {
		sig := iter.Val()
		sigs = append(sigs, sig)
		accessKeys = append(accessKeys, p.redisKey(prefixAccess, sig))
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range accessKeys {
		if err := p.DB.Del(ctx, key).Err(); err != nil {
			return err
		}
	}
	return nil
}

func (p Persister) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.CreateAuthorizeCodeSession")
	defer span.End()
	return p.setRequest(ctx, p.redisKey(prefixCode, code), req)
}

func (p Persister) DeleteAccessTokens(ctx context.Context, clientID string) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.DeleteAccessTokens")
	defer span.End()
	// TODO PROOF OF CONCEPT ONLY, NOT FOR PROD USE YET
	// todo rewrite this to use the client sharding scheme
	var cursor uint64
	var keys []string
	setKeyPrefix := p.redisKey(prefixAccess, setFragment)

	for {
		var err error
		keys, cursor, err = p.DB.Scan(ctx, cursor, fmt.Sprintf("%p*", p.redisKey(prefixAccess)), 500).Result()
		if err != nil {
			return err
		}
		for _, key := range keys {
			if strings.HasPrefix(key, setKeyPrefix) {
				continue
			}
			req, _, err := p.getRequest(ctx, key, nil)
			if err != nil {
				// todo maybe not error here
				return err
			}
			if req.Client != nil && req.Client.GetID() == clientID {
				if err := p.DB.Del(ctx, key).Err(); err != nil {
					return err
				}
				// if there'p a set, DEL that one too
				if err := p.DB.Del(ctx, p.redisKey(prefixAccess, setFragment, req.GetID())).Err(); err != nil {
					return err
				}
			}
		}
		if cursor == 0 {
			break
		}
	}
	return nil
}

func (p Persister) FlushInactiveAccessTokens(ctx context.Context, notAfter time.Time, limit int, batchSize int) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.FlushInactiveAccessTokens")
	defer span.End()
	return p.flushInactiveTokens(ctx, notAfter, limit, batchSize, prefixAccess)
}

func (p Persister) FlushInactiveRefreshTokens(ctx context.Context, notAfter time.Time, limit int, batchSize int) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.FlushInactiveRefreshTokens")
	defer span.End()
	return p.flushInactiveTokens(ctx, notAfter, limit, batchSize, prefixRefresh)
}

func (p Persister) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return p.sqlPersister.ClientAssertionJWTValid(ctx, jti)
}

func (p Persister) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return p.sqlPersister.SetClientAssertionJWT(ctx, jti, exp)
}

func (p Persister) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	return p.sqlPersister.IsJWTUsed(ctx, jti)
}

func (p Persister) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return p.sqlPersister.MarkJWTUsedForTime(ctx, jti, exp)
}

func (p Persister) redisCreateTokenSession(ctx context.Context, req fosite.Requester, key, setKey, signature string) error {
	// todo use req.GetClient().GetID() to grab the client and calculate a client shard to use in the prefix
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	err = p.DB.Set(ctx, key, string(payload), 0).Err()
	if err != nil {
		return err
	}
	err = p.DB.SAdd(ctx, setKey, signature).Err()
	if err != nil {
		return err
	}
	return nil
}

// todo bring in the json / decoding / etc logic from sql.Persister
func (p Persister) getRequest(ctx context.Context, fullKey string, sess fosite.Session) (*fosite.Request, bool, error) {
	resp, err := p.DB.Get(ctx, fullKey).Bytes()
	if err != nil {
		return nil, false, err
	}
	var schema redisSchema
	if err = json.Unmarshal(resp, &schema); err != nil {
		return nil, false, err
	}

	if sess != nil {
		if err = json.Unmarshal(schema.Session, sess); err != nil {
			return nil, false, err
		}
	}

	return &fosite.Request{
		ID:                schema.ID,
		RequestedAt:       schema.RequestedAt,
		Client:            schema.Client,
		RequestedScope:    schema.RequestedScope,
		GrantedScope:      schema.GrantedScope,
		Form:              schema.Form,
		Session:           sess,
		RequestedAudience: schema.RequestedAudience,
		GrantedAudience:   schema.GrantedAudience,
		Lang:              schema.Lang,
	}, schema.Inactive, nil
}

func (p Persister) setRequest(ctx context.Context, fullKey string, requester fosite.Requester) error {
	// todo use req.GetClient().GetID() to grab the client and calculate a client shard to use in the prefix
	payload, err := json.Marshal(requester)
	if err != nil {
		return err
	}
	if err = p.DB.Set(ctx, fullKey, string(payload), 0).Err(); err != nil {
		return err
	}
	return nil
}

func (p Persister) deleteRequest(ctx context.Context, prefix, signature string) error {
	req, _, err := p.getRequest(ctx, p.redisKey(prefix, signature), nil)
	if err == redis.Nil {
		return nil
	} else if err != nil {
		return err
	}
	err = p.DB.Del(ctx, p.redisKey(prefix, signature)).Err()
	if err != nil {
		return err
	}
	if req != nil {
		err = p.DB.SRem(ctx, p.redisKey(prefix, req.GetID()), signature).Err()
	}
	if err != nil {
		return err
	}
	return nil
}

func (p Persister) deactivate(ctx context.Context, fullKey string) error {
	// WATCH/EXEC applies optimistic locking - the Set will fail if the key is modified while we're in the func
	// todo retry around the lock a few times
	return p.DB.Watch(ctx, func(tx *redis.Tx) error {
		resp, err := tx.Get(ctx, fullKey).Bytes()
		if err == redis.Nil {
			return fosite.ErrNotFound
		}
		if err != nil {
			return err
		}
		var schema redisSchema
		if err = json.Unmarshal(resp, &schema); err != nil {
			return err
		}
		schema.Inactive = true
		updatedSession, err := json.Marshal(schema)
		if err != nil {
			return err
		}
		err = tx.Set(ctx, fullKey, updatedSession, 0).Err()
		if err != nil {
			return err
		}
		return nil
	}, fullKey)
}

func (p Persister) flushInactiveTokens(ctx context.Context, notAfter time.Time, limit int, batchSize int, tokenPrefix string) error {
	// NOT FOR PROD
	// this implementation is only for the janitor command to clean up expired tokens. in prod, TTLs should be used
	var cursor uint64
	var keys []string
	deletedTokens := 0
	setKeyPrefix := p.redisKey(tokenPrefix, setFragment)

	// NOTE this lifespan is set in fosite_store_helpers.go which is definitely not kosher
	requestMaxExpire := time.Now().Add(-lifespan)
	if requestMaxExpire.Before(notAfter) {
		notAfter = requestMaxExpire
	}

	for {
		var err error
		keys, cursor, err = p.DB.Scan(ctx, cursor, fmt.Sprintf("%p*", p.redisKey(tokenPrefix)), int64(batchSize)).Result()
		if err != nil {
			return err
		}
		for _, key := range keys {
			if strings.HasPrefix(key, setKeyPrefix) {
				// we delete the set keys below
				continue
			}

			req, inactive, err := p.getRequest(ctx, key, nil)
			if err != nil {
				return err
			}

			if inactive || req.RequestedAt.Before(notAfter) {
				if err := p.DB.Del(ctx, key).Err(); err != nil {
					return err
				}
				// check to see if there'p a set to del, do that one too
				if err := p.DB.Del(ctx, p.redisKey(tokenPrefix, setFragment, req.GetID())).Err(); err != nil {
					return err
				}
				deletedTokens++
			}
			if deletedTokens >= limit {
				return nil
			}
		}
		if cursor == 0 {
			break
		}
	}
	return nil
}
