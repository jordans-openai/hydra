package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/persistence"
	"golang.org/x/text/language"
	"gopkg.in/square/go-jose.v2"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
)

type FositeRedisStorePersister interface {
	AssertionJWTReader
	persistence.Persister
}

type FositeRedisStore struct {
	DB        redis.UniversalClient
	KeyPrefix string
	Persister FositeRedisStorePersister
}

const (
	prefixOIDC    = "oidc"
	prefixAccess  = "accs"
	prefixRefresh = "refr"
	prefixCode    = "code"
	prefixPKCE    = "pkce"
	setFragment   = "s"
	clientShards  = 128
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

	// field to track revocation
	Inactive bool `json:"inactive"`
}

func (s FositeRedisStore) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) error {
	return s.setRequest(ctx, s.redisKey(prefixOIDC, authorizeCode), req)
}

func (s FositeRedisStore) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, req fosite.Requester) (fosite.Requester, error) {
	r, _, err := s.getRequest(ctx, s.redisKey(prefixOIDC, authorizeCode), req.GetSession())
	if err == redis.Nil {
		return nil, fosite.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "storage error")
	}

	return r, nil
}

func (s FositeRedisStore) GetAuthorizeCodeSession(ctx context.Context, code string, sess fosite.Session) (fosite.Requester, error) {
	req, inactive, err := s.getRequest(ctx, s.redisKey(prefixCode, code), sess)
	if err == redis.Nil {
		return nil, fosite.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "storage error")
	} else if inactive {
		return req, fosite.ErrInvalidatedAuthorizeCode
	}

	return req, nil
}

func (s FositeRedisStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return s.deactivate(ctx, s.redisKey(prefixCode, code))
}

func (s FositeRedisStore) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	req, _, err := s.getRequest(ctx, s.redisKey(prefixPKCE, signature), session)
	if err == redis.Nil {
		return nil, fosite.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "storage error")
	}
	return req, nil
}

func (s FositeRedisStore) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	return s.setRequest(ctx, s.redisKey(prefixPKCE, signature), requester)
}

func (s FositeRedisStore) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.deleteRequest(ctx, prefixPKCE, signature)
}

func (s FositeRedisStore) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	return s.redisCreateTokenSession(
		ctx,
		req,
		s.redisKey(prefixAccess, signature),
		s.redisKey(prefixAccess, setFragment, req.GetID()),
		signature,
	)
}

func (s FositeRedisStore) GetAccessTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	fmt.Println("GetAccessTokenSession", signature, sess)
	req, _, err := s.getRequest(ctx, s.redisKey(prefixAccess, signature), sess)
	if err == redis.Nil {
		return nil, fosite.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "storage error")
	}

	return req, nil
}

func (s FositeRedisStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.deleteRequest(ctx, prefixAccess, signature)
}

func (s FositeRedisStore) CreateRefreshTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	return s.redisCreateTokenSession(
		ctx,
		req,
		s.redisKey(prefixRefresh, signature),
		s.redisKey(prefixRefresh, setFragment, req.GetID()),
		signature,
	)
}

func (s FositeRedisStore) GetRefreshTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	session, inactive, err := s.getRequest(ctx, s.redisKey(prefixRefresh, signature), sess)
	if err == redis.Nil {
		return nil, fosite.ErrNotFound
	} else if err != nil {
		return nil, errors.Wrap(err, "storage error")
	} else if inactive {
		return session, fosite.ErrInactiveToken
	}
	return session, nil
}

func (s FositeRedisStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.deleteRequest(ctx, prefixRefresh, signature)
}

func (s FositeRedisStore) CreateImplicitAccessTokenSession(ctx context.Context, code string, req fosite.Requester) error {
	return s.CreateAccessTokenSession(ctx, code, req)
}

func (s FositeRedisStore) PersistAuthorizeCodeGrantSession(ctx context.Context, authorizeCode, accessSignature, refreshSignature string, req fosite.Requester) error {
	if err := s.DB.Del(ctx, s.redisKey(prefixCode, authorizeCode)).Err(); err != nil {
		return err
	} else if err = s.CreateAccessTokenSession(ctx, accessSignature, req); err != nil {
		return err
	}
	if refreshSignature == "" {
		return nil
	}
	if err := s.CreateRefreshTokenSession(ctx, refreshSignature, req); err != nil {
		return err
	}
	return nil
}

func (s FositeRedisStore) PersistRefreshTokenGrantSession(ctx context.Context, originalRefreshSignature, accessSignature, refreshSignature string, req fosite.Requester) error {
	if err := s.DeleteRefreshTokenSession(ctx, originalRefreshSignature); err != nil {
		return err
	} else if err = s.CreateAccessTokenSession(ctx, accessSignature, req); err != nil {
		return err
	} else if err = s.CreateRefreshTokenSession(ctx, refreshSignature, req); err != nil {
		return err
	}
	return nil
}

func (s FositeRedisStore) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return s.DB.Del(ctx, s.redisKey(prefixOIDC, authorizeCode)).Err()
}

func (s FositeRedisStore) RevokeRefreshToken(ctx context.Context, id string) error {
	refreshSet := s.redisKey(prefixRefresh, setFragment, id)
	iter := s.DB.SScan(ctx, refreshSet, 0, "", 500).Iterator()
	sigs := make([]interface{}, 0)
	refreshKeys := make([]string, 0)
	for iter.Next(ctx) {
		sig := iter.Val()
		sigs = append(sigs, sig)
		refreshKeys = append(refreshKeys, s.redisKey(prefixRefresh, sig))
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range refreshKeys {
		if err := s.deactivate(ctx, key); err != nil {
			return err
		}
	}
	return nil
}

func (s FositeRedisStore) RevokeAccessToken(ctx context.Context, id string) error {
	accessSet := s.redisKey(prefixAccess, setFragment, id)
	iter := s.DB.SScan(ctx, accessSet, 0, "", 500).Iterator()
	sigs := make([]interface{}, 0)
	accessKeys := make([]string, 0)
	for iter.Next(ctx) {
		sig := iter.Val()
		sigs = append(sigs, sig)
		accessKeys = append(accessKeys, s.redisKey(prefixAccess, sig))
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range accessKeys {
		if err := s.DB.Del(ctx, key).Err(); err != nil {
			return err
		}
	}
	return nil
}

func (s FositeRedisStore) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	return s.setRequest(ctx, s.redisKey(prefixCode, code), req)
}

func (s FositeRedisStore) DeleteAccessTokens(ctx context.Context, clientID string) error {
	// TODO PROOF OF CONCEPT ONLY, NOT FOR PROD USE YET
	// todo rewrite this to use the client sharding scheme
	var cursor uint64
	var keys []string
	setKeyPrefix := s.redisKey(prefixAccess, setFragment)

	for {
		var err error
		keys, cursor, err = s.DB.Scan(ctx, cursor, fmt.Sprintf("%s*", s.redisKey(prefixAccess)), 500).Result()
		if err != nil {
			return err
		}
		for _, key := range keys {
			if strings.HasPrefix(key, setKeyPrefix) {
				continue
			}
			req, _, err := s.getRequest(ctx, key, nil)
			if err != nil {
				// todo maybe not error here
				return err
			}
			if req.Client != nil && req.Client.GetID() == clientID {
				if err := s.DB.Del(ctx, key).Err(); err != nil {
					return err
				}
				// if there's a set, DEL that one too
				if err := s.DB.Del(ctx, s.redisKey(prefixAccess, setFragment, req.GetID())).Err(); err != nil {
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

func (s FositeRedisStore) FlushInactiveLoginConsentRequests(ctx context.Context, notAfter time.Time, limit int, batchSize int) error {
	// will not implement - this is only for the janitor command to clean up expired tokens. we should use redis TTLs for this
	return nil
}

func (s FositeRedisStore) FlushInactiveAccessTokens(ctx context.Context, notAfter time.Time, limit int, batchSize int) error {
	return s.flushInactiveTokens(ctx, notAfter, limit, batchSize, prefixAccess)
}

func (s FositeRedisStore) FlushInactiveRefreshTokens(ctx context.Context, notAfter time.Time, limit int, batchSize int) error {
	return s.flushInactiveTokens(ctx, notAfter, limit, batchSize, prefixRefresh)
}

// Delegate all hydra_client storage to s.Persister (SQL) - these queries don't need to scale to the same level

func (s FositeRedisStore) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	return s.Persister.GetPublicKey(ctx, issuer, subject, keyId)
}

func (s FositeRedisStore) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	return s.Persister.GetPublicKeys(ctx, issuer, subject)
}

func (s FositeRedisStore) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	return s.Persister.GetPublicKeyScopes(ctx, issuer, subject, keyId)
}

func (s FositeRedisStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	return s.Persister.IsJWTUsed(ctx, jti)
}

func (s FositeRedisStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return s.Persister.MarkJWTUsedForTime(ctx, jti, exp)
}

func (s FositeRedisStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	return s.Persister.GetConcreteClient(ctx, id)
}

func (s FositeRedisStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return s.Persister.ClientAssertionJWTValid(ctx, jti)
}

func (s FositeRedisStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return s.Persister.SetClientAssertionJWT(ctx, jti, exp)
}

func (s FositeRedisStore) GetClientAssertionJWT(ctx context.Context, jti string) (*BlacklistedJTI, error) {
	return s.Persister.GetClientAssertionJWT(ctx, jti)
}

func (s FositeRedisStore) SetClientAssertionJWTRaw(ctx context.Context, jti *BlacklistedJTI) error {
	return s.Persister.SetClientAssertionJWTRaw(ctx, jti)
}

func (s FositeRedisStore) redisCreateTokenSession(ctx context.Context, req fosite.Requester, key, setKey, signature string) error {
	// todo use req.GetClient().GetID() to grab the client and calculate a client shard to use in the prefix
	payload, err := json.Marshal(req)
	if err != nil {
		return err
	}
	err = s.DB.Set(ctx, key, string(payload), 0).Err()
	if err != nil {
		return err
	}
	err = s.DB.SAdd(ctx, setKey, signature).Err()
	if err != nil {
		return err
	}
	return nil
}

// todo this might not be sufficient - some fosite.Requester implementations have more fields than fosite.Request
func (s FositeRedisStore) getRequest(ctx context.Context, fullKey string, sess fosite.Session) (*fosite.Request, bool, error) {
	resp, err := s.DB.Get(ctx, fullKey).Bytes()
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

func (s FositeRedisStore) setRequest(ctx context.Context, fullKey string, requester fosite.Requester) error {
	// todo use req.GetClient().GetID() to grab the client and calculate a client shard to use in the prefix
	payload, err := json.Marshal(requester)
	if err != nil {
		return err
	}
	if err = s.DB.Set(ctx, fullKey, string(payload), 0).Err(); err != nil {
		return err
	}
	return nil
}

func (s FositeRedisStore) deleteRequest(ctx context.Context, prefix, signature string) error {
	req, _, err := s.getRequest(ctx, s.redisKey(prefix, signature), nil)
	if err == redis.Nil {
		return nil
	} else if err != nil {
		return err
	}
	err = s.DB.Del(ctx, s.redisKey(prefix, signature)).Err()
	if err != nil {
		return err
	}
	if req != nil {
		err = s.DB.SRem(ctx, s.redisKey(prefix, req.GetID()), signature).Err()
	}
	if err != nil {
		return err
	}
	return nil
}

func (s FositeRedisStore) deactivate(ctx context.Context, fullKey string) error {
	// WATCH/EXEC applies optimistic locking - the Set will fail if the key is modified while we're in the func
	return s.DB.Watch(ctx, func(tx *redis.Tx) error {
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

func (s FositeRedisStore) flushInactiveTokens(ctx context.Context, notAfter time.Time, limit int, batchSize int, tokenPrefix string) error {
	// NOT FOR PROD
	// this implementation is only for the janitor command to clean up expired tokens. in prod, TTLs should be used
	var cursor uint64
	var keys []string
	deletedTokens := 0
	setKeyPrefix := s.redisKey(tokenPrefix, setFragment)

	// NOTE this lifespan is set in fosite_store_helpers.go which is definitely not kosher
	requestMaxExpire := time.Now().Add(-lifespan)
	if requestMaxExpire.Before(notAfter) {
		notAfter = requestMaxExpire
	}

	for {
		var err error
		keys, cursor, err = s.DB.Scan(ctx, cursor, fmt.Sprintf("%s*", s.redisKey(tokenPrefix)), int64(batchSize)).Result()
		if err != nil {
			return err
		}
		for _, key := range keys {
			if strings.HasPrefix(key, setKeyPrefix) {
				// we delete the set keys below
				continue
			}

			req, inactive, err := s.getRequest(ctx, key, nil)
			if err != nil {
				return err
			}

			if inactive || req.RequestedAt.Before(notAfter) {
				if err := s.DB.Del(ctx, key).Err(); err != nil {
					return err
				}
				// check to see if there's a set to del, do that one too
				if err := s.DB.Del(ctx, s.redisKey(tokenPrefix, setFragment, req.GetID())).Err(); err != nil {
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

func (s FositeRedisStore) redisKey(fields ...string) string {
	return s.KeyPrefix + strings.Join(fields, ":")
}
