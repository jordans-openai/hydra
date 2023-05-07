package redis

import (
	"context"
	"encoding/json"
	"github.com/ory/fosite"
	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/consent"
	"github.com/ory/hydra/v2/flow"
	"github.com/ory/hydra/v2/x"
	"github.com/ory/x/errorsx"
	"github.com/ory/x/sqlxx"
	"github.com/pkg/errors"
	"github.com/redis/go-redis/v9"
	"time"
)

var (
	indexBySubject            = "by_subject"
	indexByConsentChallengeID = "by_consent_challenge_id"
	indexByConsentVerifier    = "by_consent_verifier"
	indexByLoginVerifier      = "by_login_verifier"
)

func (p Persister) CreateConsentRequest(ctx context.Context, req *consent.OAuth2ConsentRequest) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.CreateConsentRequest")
	defer span.End()

	id := req.LoginChallenge.String()
	return p.updateFlow(ctx, p.redisKey(prefixFlow, id), func(f *flow.Flow) (*flow.Flow, error) {
		f.State = flow.FlowStateConsentInitialized
		f.ConsentChallengeID = sqlxx.NullString(req.ID)
		f.ConsentSkip = req.Skip
		f.ConsentVerifier = sqlxx.NullString(req.Verifier)
		f.ConsentCSRF = sqlxx.NullString(req.CSRF)
		f.NID = p.NetworkID(ctx)
		return f, nil
	})
}

func (p Persister) GetConsentRequest(ctx context.Context, challenge string) (*consent.OAuth2ConsentRequest, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.GetConsentRequest")
	defer span.End()

	f, err := p.findFlowByIndex(ctx, indexByConsentChallengeID, challenge)
	if err != nil {
		if err == redis.Nil {
			return nil, errorsx.WithStack(x.ErrNotFound)
		}
		return nil, err
	}
	cs := f.GetConsentRequest()
	if cs.AMR == nil {
		cs.AMR = []string{}
	}
	return cs, nil
}

func (p Persister) HandleConsentRequest(ctx context.Context, r *consent.AcceptOAuth2ConsentRequest) (*consent.OAuth2ConsentRequest, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.HandleConsentRequest")
	defer span.End()

	fk, err := p.findFlowKeyByIndex(ctx, indexByConsentChallengeID, r.ID)
	if err != nil && err == redis.Nil {
		return nil, err
	}
	err = p.updateFlow(ctx, fk, func(f *flow.Flow) (*flow.Flow, error) {
		if err = f.HandleConsentRequest(r); err != nil {
			return nil, errorsx.WithStack(err)
		}
		return f, nil
	})

	if err != nil {
		return nil, err
	}

	return p.GetConsentRequest(ctx, r.ID)
}

func (p Persister) RevokeSubjectConsentSession(ctx context.Context, subject string) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.RevokeSubjectConsentSession")
	defer span.End()

	return p.revokeConsentSession(ctx, subject, "")
}

func (p Persister) RevokeSubjectClientConsentSession(ctx context.Context, subject, client string) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.RevokeSubjectClientConsentSession")
	defer span.End()

	return p.revokeConsentSession(ctx, subject, client)
}

func (p Persister) VerifyAndInvalidateConsentRequest(ctx context.Context, verifier string) (*consent.AcceptOAuth2ConsentRequest, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.VerifyAndInvalidateConsentRequest")
	defer span.End()

	fk, err := p.findFlowKeyByIndex(ctx, indexByConsentVerifier, verifier)
	if err != nil {
		return nil, err
	}
	var r consent.AcceptOAuth2ConsentRequest
	return &r, p.updateFlow(ctx, fk, func(f *flow.Flow) (*flow.Flow, error) {
		if err := f.InvalidateConsentRequest(); err != nil {
			return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithDebug(err.Error()))
		}
		r = *f.GetHandledConsentRequest()
		return f, nil
	})
}

func (p Persister) FindGrantedAndRememberedConsentRequests(ctx context.Context, client, subject string) ([]consent.AcceptOAuth2ConsentRequest, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.FindGrantedAndRememberedConsentRequests")
	defer span.End()

	flows, err := p.findFlowsByIndex(ctx, indexBySubject, subject)
	if err != nil {
		return nil, err
	}
	var found *flow.Flow
	for _, f := range flows {
		if (f.State == flow.FlowStateConsentUsed || f.State == flow.FlowStateConsentUnused) &&
			f.ClientID == client &&
			!f.ConsentSkip &&
			f.ConsentError == nil && // todo might need to check against "{}"?
			f.ConsentRemember &&
			f.NID == p.NetworkID(ctx) {
			if found != nil && f.RequestedAt.Before(found.RequestedAt) {
				continue
			}
			found = f
		}
	}
	if found == nil {
		return nil, errorsx.WithStack(consent.ErrNoPreviousConsentFound)
	}
	return p.filterExpiredConsentRequests(ctx, []consent.AcceptOAuth2ConsentRequest{*found.GetHandledConsentRequest()})
}

func (p Persister) FindSubjectsGrantedConsentRequests(ctx context.Context, subject string, limit, offset int) ([]consent.AcceptOAuth2ConsentRequest, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.FindSubjectsGrantedConsentRequests")
	defer span.End()

	// todo for now, ignoring limit and offset
	results := make([]flow.Flow, 0)

	flows, err := p.findFlowsByIndex(ctx, indexBySubject, subject)
	if err != nil {
		return nil, err
	}
	for _, f := range flows {
		if (f.State == flow.FlowStateConsentUsed || f.State == flow.FlowStateConsentUnused) &&
			!f.ConsentSkip &&
			f.ConsentError == nil && // todo might need to check against "{}"?
			f.NID == p.NetworkID(ctx) {
			results = append(results, *f)
		}
	}

	if len(results) == 0 {
		return nil, errorsx.WithStack(consent.ErrNoPreviousConsentFound)
	}
	var rs []consent.AcceptOAuth2ConsentRequest
	for _, f := range flows {
		rs = append(rs, *f.GetHandledConsentRequest())
	}
	return p.filterExpiredConsentRequests(ctx, rs)
}

func (p Persister) FindSubjectsSessionGrantedConsentRequests(ctx context.Context, subject, sid string, limit, offset int) ([]consent.AcceptOAuth2ConsentRequest, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.FindSubjectsSessionGrantedConsentRequests")
	defer span.End()

	// todo for now, ignoring limit and offset
	results := make([]flow.Flow, 0)

	flows, err := p.findFlowsByIndex(ctx, indexBySubject, subject)
	if err != nil {
		return nil, err
	}
	for _, f := range flows {
		if (f.State == flow.FlowStateConsentUsed || f.State == flow.FlowStateConsentUnused) &&
			f.SessionID.String() == sid &&
			!f.ConsentSkip &&
			f.ConsentError == nil && // todo might need to check against "{}"?
			f.NID == p.NetworkID(ctx) {
			results = append(results, *f)
		}
	}

	if len(results) == 0 {
		return nil, errorsx.WithStack(consent.ErrNoPreviousConsentFound)
	}
	var rs []consent.AcceptOAuth2ConsentRequest
	for _, f := range flows {
		rs = append(rs, *f.GetHandledConsentRequest())
	}
	return p.filterExpiredConsentRequests(ctx, rs)
}

func (p Persister) CountSubjectsGrantedConsentRequests(ctx context.Context, subject string) (int, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.CountSubjectsGrantedConsentRequests")
	defer span.End()

	flows, err := p.findFlowsByIndex(ctx, indexBySubject, subject)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, f := range flows {
		if (f.State == flow.FlowStateConsentUsed || f.State == flow.FlowStateConsentUnused) &&
			!f.ConsentSkip &&
			f.ConsentError == nil && // todo might need to check against "{}"?
			f.NID == p.NetworkID(ctx) {
			count += 1
		}
	}
	return count, nil
}

func (p Persister) GetRememberedLoginSession(ctx context.Context, id string) (*consent.LoginSession, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.GetRememberedLoginSession")
	defer span.End()

	session, err := p.getAuthenticationSession(ctx, p.DB, id)
	if err != nil {
		return nil, err
	}
	if !session.Remember {
		return nil, errorsx.WithStack(x.ErrNotFound)
	}
	return session, nil
}

func (p Persister) CreateLoginSession(ctx context.Context, session *consent.LoginSession) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.CreateLoginSession")
	defer span.End()

	return p.setAuthenticationSession(ctx, p.redisKey(prefixAuthenticationSession, session.ID), session)
}

func (p Persister) DeleteLoginSession(ctx context.Context, id string) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.DeleteLoginSession")
	defer span.End()

	return p.deleteAuthenticationSession(ctx, id)

}

func (p Persister) RevokeSubjectLoginSession(ctx context.Context, subject string) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.RevokeSubjectLoginSession")
	defer span.End()

	sessions, err := p.findAuthenticationSessionsByIndex(ctx, indexBySubject, subject)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if err := p.deleteAuthenticationSession(ctx, session.ID); err != nil {
			return err
		}
	}
	return nil
}

func (p Persister) ConfirmLoginSession(ctx context.Context, id string, authTime time.Time, subject string, remember bool) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.ConfirmLoginSession")
	defer span.End()

	return p.updateAuthenticationSession(ctx, id, func(s *consent.LoginSession) (*consent.LoginSession, error) {
		s.AuthenticatedAt = sqlxx.NullTime(authTime)
		s.Subject = subject
		s.Remember = remember
		return s, nil
	})
}

func (p Persister) CreateLoginRequest(ctx context.Context, req *consent.LoginRequest) error {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.CreateLoginRequest")
	defer span.End()

	f := flow.NewFlow(req)
	return p.setFlow(ctx, p.redisKey(prefixFlow, f.ID), f)
}

func (p Persister) GetLoginRequest(ctx context.Context, challenge string) (*consent.LoginRequest, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.GetLoginRequest")
	defer span.End()

	f, err := p.getFlowByID(ctx, p.DB, p.redisKey(prefixFlow, challenge))
	if err == redis.Nil {
		return nil, errorsx.WithStack(x.ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	return f.GetLoginRequest(), nil
}

func (p Persister) HandleLoginRequest(ctx context.Context, challenge string, r *consent.HandledLoginRequest) (*consent.LoginRequest, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.HandleLoginRequest")
	defer span.End()

	key := p.redisKey(prefixFlow, challenge)
	err := p.updateFlow(ctx, key, func(f *flow.Flow) (*flow.Flow, error) {
		err := f.HandleLoginRequest(r)
		if err != nil {
			return nil, err
		}
		return f, nil
	})
	if err != nil {
		return nil, err
	}
	// the sql version makes another read from db, so we will too
	return p.GetLoginRequest(ctx, challenge)
}

func (p Persister) VerifyAndInvalidateLoginRequest(ctx context.Context, verifier string) (*consent.HandledLoginRequest, error) {
	ctx, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.VerifyAndInvalidateLoginRequest")
	defer span.End()

	key, err := p.findFlowKeyByIndex(ctx, indexByLoginVerifier, verifier)
	if err != nil {
		return nil, err
	}

	var d consent.HandledLoginRequest
	err = p.updateFlow(ctx, key, func(f *flow.Flow) (*flow.Flow, error) {
		err := f.InvalidateLoginRequest()
		if err != nil {
			return nil, errorsx.WithStack(fosite.ErrInvalidRequest.WithDebug(err.Error()))
		}
		d = f.GetHandledLoginRequest()
		return f, nil
	})
	if err != nil {
		return nil, err
	}
	return &d, nil
}

func (p Persister) FlushInactiveLoginConsentRequests(ctx context.Context, notAfter time.Time, limit int, batchSize int) error {
	// todo implement this. similar to oauth2 table, we should just rely on redis TTLs for this if we can
	return p.sqlPersister.FlushInactiveLoginConsentRequests(ctx, notAfter, limit, batchSize)
}
func (p Persister) CreateForcedObfuscatedLoginSession(ctx context.Context, session *consent.ForcedObfuscatedLoginSession) error {
	// todo implement
	return p.sqlPersister.CreateForcedObfuscatedLoginSession(ctx, session)
}

func (p Persister) GetForcedObfuscatedLoginSession(ctx context.Context, client, obfuscated string) (*consent.ForcedObfuscatedLoginSession, error) {
	// todo implement
	return p.sqlPersister.GetForcedObfuscatedLoginSession(ctx, client, obfuscated)
}

// the following two methods use a JOIN between clients and flows tables

func (p Persister) ListUserAuthenticatedClientsWithFrontChannelLogout(ctx context.Context, subject, sid string) ([]client.Client, error) {
	// todo implement
	return p.sqlPersister.ListUserAuthenticatedClientsWithFrontChannelLogout(ctx, subject, sid)
}

func (p Persister) ListUserAuthenticatedClientsWithBackChannelLogout(ctx context.Context, subject, sid string) ([]client.Client, error) {
	// todo implement
	return p.sqlPersister.ListUserAuthenticatedClientsWithBackChannelLogout(ctx, subject, sid)
}

func (p Persister) CreateLogoutRequest(ctx context.Context, request *consent.LogoutRequest) error {
	// todo implement
	return p.sqlPersister.CreateLogoutRequest(ctx, request)
}

func (p Persister) GetLogoutRequest(ctx context.Context, challenge string) (*consent.LogoutRequest, error) {
	// todo implement
	return p.sqlPersister.GetLogoutRequest(ctx, challenge)
}

func (p Persister) AcceptLogoutRequest(ctx context.Context, challenge string) (*consent.LogoutRequest, error) {
	// todo implement
	return p.sqlPersister.AcceptLogoutRequest(ctx, challenge)
}

func (p Persister) RejectLogoutRequest(ctx context.Context, challenge string) error {
	// todo implement
	return p.sqlPersister.RejectLogoutRequest(ctx, challenge)
}

func (p Persister) VerifyAndInvalidateLogoutRequest(ctx context.Context, verifier string) (*consent.LogoutRequest, error) {
	// todo implement
	return p.sqlPersister.VerifyAndInvalidateLogoutRequest(ctx, verifier)
}

func (p *Persister) filterExpiredConsentRequests(ctx context.Context, requests []consent.AcceptOAuth2ConsentRequest) ([]consent.AcceptOAuth2ConsentRequest, error) {
	_, span := p.r.Tracer(ctx).Tracer().Start(ctx, "persistence.redis.filterExpiredConsentRequests")
	defer span.End()

	var result []consent.AcceptOAuth2ConsentRequest
	for _, v := range requests {
		if v.RememberFor > 0 && v.RequestedAt.Add(time.Duration(v.RememberFor)*time.Second).Before(time.Now().UTC()) {
			continue
		}
		result = append(result, v)
	}
	if len(result) == 0 {
		return nil, errorsx.WithStack(consent.ErrNoPreviousConsentFound)
	}
	return result, nil
}

// -- authentication_sessions --

func (p Persister) getAuthenticationSession(ctx context.Context, rr redis.Cmdable, id string) (*consent.LoginSession, error) {
	ls, err := rr.Get(ctx, p.redisKey(prefixAuthenticationSession, id)).Bytes()
	if err == redis.Nil {
		return nil, errorsx.WithStack(x.ErrNotFound)
	} else if err != nil {
		return nil, errorsx.WithStack(err)
	}
	var session consent.LoginSession
	if err := json.Unmarshal(ls, &session); err != nil {
		return nil, errorsx.WithStack(err)
	}
	return &session, nil
}

func (p Persister) setAuthenticationSession(ctx context.Context, key string, ls *consent.LoginSession) error {
	data, err := json.Marshal(ls)
	if err != nil {
		return err
	}
	// todo set expiration!!
	err = p.DB.Set(ctx, key, data, 0).Err()
	if err != nil {
		return err
	}

	if ls.Subject != "" {
		if err := p.DB.SAdd(ctx, p.redisKey(prefixAuthenticationSession, indexBySubject, ls.Subject), key).Err(); err != nil {
			return err
		}
	}

	return nil
}

func (p Persister) deleteAuthenticationSession(ctx context.Context, id string) error {
	key := p.redisKey(prefixAuthenticationSession, id)
	// let the WATCH silently fail if someone else writes a new key here or updates it
	var session *consent.LoginSession
	err := p.DB.Watch(ctx, func(tx *redis.Tx) error {
		var err error
		session, err = p.getAuthenticationSession(ctx, tx, id)
		c, err := tx.Del(ctx, key).Result()
		if err != nil {
			return errorsx.WithStack(err)
		}
		if c == 0 {
			return errorsx.WithStack(x.ErrNotFound)
		}
		return nil
	}, key)
	if err != nil {
		return err
	}
	_ = p.DB.SRem(ctx, p.redisKey(prefixAuthenticationSession, indexBySubject, session.Subject), key).Err()
	return nil
}

func (p Persister) findAuthenticationSessionsByIndex(ctx context.Context, index, value string) ([]*consent.LoginSession, error) {
	ids, err := p.DB.SMembers(ctx, p.redisKey(prefixAuthenticationSession, index, value)).Result()
	if err != nil {
		return nil, err
	}
	var result []*consent.LoginSession
	for _, id := range ids {
		session, err := p.getAuthenticationSession(ctx, p.DB, id)
		if err != nil {
			return nil, err
		}
		result = append(result, session)
	}
	return result, nil
}

func (p Persister) updateAuthenticationSession(ctx context.Context, id string, f func(*consent.LoginSession) (*consent.LoginSession, error)) error {
	var oldSubject string
	var updated *consent.LoginSession
	// todo retry around the optimistic lock a few times
	key := p.redisKey(prefixAuthenticationSession, id)
	err := p.DB.Watch(ctx, func(tx *redis.Tx) error {
		as, err := p.getAuthenticationSession(ctx, tx, id)
		if err != nil {
			return err
		}
		oldSubject = as.Subject

		updated, err = f(as)
		if err != nil {
			return err
		}
		data, err := json.Marshal(updated)
		if err != nil {
			return err
		}
		err = tx.Set(ctx, key, data, 0).Err()
		if err != nil {
			return err
		}

		return nil
	}, key)
	if err != nil {
		return err
	}
	return p.reindexIfChanged(ctx, prefixAuthenticationSession, indexBySubject, oldSubject, updated.Subject, key)
}

// -- flows --

func (p Persister) revokeConsentSession(ctx context.Context, subject, client string) error {
	flows, err := p.findFlowsByIndex(ctx, indexBySubject, subject)
	if err != nil {
		return err
	}

	if client != "" {
		var filteredFlows []*flow.Flow
		for _, f := range flows {
			if f.ClientID == client {
				filteredFlows = append(filteredFlows, f)
			}
		}
		flows = filteredFlows
	}

	hasConsentChallengeID := false
	for _, f := range flows {
		if f.ConsentChallengeID != "" {
			hasConsentChallengeID = true
			break
		}
	}
	if !hasConsentChallengeID {
		return errorsx.WithStack(x.ErrNotFound)
	}

	var count int
	for _, f := range flows {
		if err := p.RevokeAccessToken(ctx, f.ConsentChallengeID.String()); errors.Is(err, fosite.ErrNotFound) {
			// do nothing
		} else if err != nil {
			return err
		}
		if err := p.RevokeRefreshToken(ctx, f.ConsentChallengeID.String()); errors.Is(err, fosite.ErrNotFound) {
			// do nothing
		} else if err != nil {
			return err
		}
		// delete the flow from redis
		fk, err := p.findFlowKeysByIndex(ctx, indexByConsentChallengeID, f.ConsentChallengeID.String())
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return errorsx.WithStack(x.ErrNotFound)
			}
		}
		for _, k := range fk {
			if err := p.DB.Del(ctx, k).Err(); err != nil {
				return err
			}
			count += 1
		}
	}
	if count == 0 {
		return errorsx.WithStack(x.ErrNotFound)
	}

	return nil
}

func (p Persister) getFlowByID(ctx context.Context, rr redis.Cmdable, key string) (*flow.Flow, error) {
	data, err := rr.Get(ctx, key).Bytes()
	if err != nil {
		return nil, err
	}
	var f flow.Flow
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	f.Client, err = p.GetConcreteClient(ctx, f.ClientID)
	return &f, err
}

func (p Persister) setFlow(ctx context.Context, key string, flow *flow.Flow) error {
	flow.ClientID = flow.Client.GetID()
	data, err := json.Marshal(flow)
	if err != nil {
		return err
	}
	// todo set expiration!!
	err = p.DB.Set(ctx, key, data, 0).Err()
	if err != nil {
		return err
	}

	if flow.Subject != "" {
		if err := p.DB.SAdd(ctx, p.redisKey(prefixFlow, indexBySubject, flow.Subject), key).Err(); err != nil {
			return err
		}
	}
	if flow.ConsentChallengeID != "" {
		if err := p.DB.SAdd(ctx, p.redisKey(prefixFlow, indexByConsentChallengeID, flow.ConsentChallengeID.String()), key).Err(); err != nil {
			return err
		}
	}
	if flow.ConsentVerifier != "" {
		if err := p.DB.SAdd(ctx, p.redisKey(prefixFlow, indexByConsentVerifier, flow.ConsentVerifier.String()), key).Err(); err != nil {
			return err
		}
	}
	if flow.LoginVerifier != "" {
		if err := p.DB.SAdd(ctx, p.redisKey(prefixFlow, indexByLoginVerifier, flow.LoginVerifier), key).Err(); err != nil {
			return err
		}
	}
	return nil
}

func (p Persister) updateFlow(ctx context.Context, key string, f func(*flow.Flow) (*flow.Flow, error)) error {
	var oldSubject, oldConsentChallengeID, oldConsentVerifier, oldLoginVerifier string
	var updatedFlow *flow.Flow
	// todo retry around the optimistic lock a few times
	err := p.DB.Watch(ctx, func(tx *redis.Tx) error {
		fl, err := p.getFlowByID(ctx, tx, key)
		if err != nil {
			return err
		}
		oldSubject = fl.Subject
		oldConsentChallengeID = fl.ConsentChallengeID.String()
		oldConsentVerifier = fl.ConsentVerifier.String()
		oldLoginVerifier = fl.LoginVerifier

		updatedFlow, err = f(fl)
		if err != nil {
			return err
		}
		data, err := json.Marshal(updatedFlow)
		if err != nil {
			return err
		}
		err = tx.Set(ctx, key, data, 0).Err()
		if err != nil {
			return err
		}

		return nil
	}, key)
	if err != nil {
		return err
	}
	err = p.reindexIfChanged(ctx, prefixFlow, indexBySubject, oldSubject, updatedFlow.Subject, key)
	if err != nil {
		return err
	}
	err = p.reindexIfChanged(ctx, prefixFlow, indexByConsentChallengeID, oldConsentChallengeID, updatedFlow.ConsentChallengeID.String(), key)
	if err != nil {
		return err
	}
	err = p.reindexIfChanged(ctx, prefixFlow, indexByConsentVerifier, oldConsentVerifier, updatedFlow.ConsentVerifier.String(), key)
	if err != nil {
		return err
	}
	err = p.reindexIfChanged(ctx, prefixFlow, indexByLoginVerifier, oldLoginVerifier, updatedFlow.LoginVerifier, key)
	if err != nil {
		return err
	}
	return nil
}

func (p Persister) findFlowByIndex(ctx context.Context, index, indexValue string) (*flow.Flow, error) {
	key, err := p.findFlowKeyByIndex(ctx, index, indexValue)
	if err != nil {
		return nil, err
	}
	return p.getFlowByID(ctx, p.DB, key)
}

func (p Persister) findFlowsByIndex(ctx context.Context, index, indexValue string) ([]*flow.Flow, error) {
	keys, err := p.findFlowKeysByIndex(ctx, index, indexValue)
	if err != nil {
		return nil, err
	}
	res := make([]*flow.Flow, 0)
	// todo parallelize? could be one MGET per shard
	for _, key := range keys {
		f, err := p.getFlowByID(ctx, p.DB, key)
		if err == nil {
			res = append(res, f)
		}
	}
	return res, nil
}

func (p Persister) findFlowKeyByIndex(ctx context.Context, index, indexValue string) (string, error) {
	keys, err := p.findFlowKeysByIndex(ctx, index, indexValue)
	if err != nil {
		return "", err
	}
	if len(keys) == 0 {
		return "", x.ErrNotFound
	}
	return keys[0], nil
}

func (p Persister) findFlowKeysByIndex(ctx context.Context, index, indexValue string) ([]string, error) {
	return p.DB.SMembers(ctx, p.redisKey(prefixFlow, index, indexValue)).Result()
}

func (p Persister) reindexIfChanged(ctx context.Context, prefix, index, oldValue, newValue, key string) error {
	if oldValue != newValue {
		if oldValue != "" {
			_ = p.DB.SRem(ctx, p.redisKey(prefix, index, oldValue), key).Err()
		}
		if newValue != "" {
			if err := p.DB.SAdd(ctx, p.redisKey(prefix, index, newValue), key).Err(); err != nil {
				return err
			}
		}
	}
	return nil
}
