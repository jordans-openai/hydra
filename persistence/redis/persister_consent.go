package redis

import (
	"context"
	"github.com/ory/hydra/v2/client"
	"github.com/ory/hydra/v2/consent"
	"time"
)

func (p Persister) CreateConsentRequest(ctx context.Context, req *consent.OAuth2ConsentRequest) error {
	return p.sqlPersister.CreateConsentRequest(ctx, req)
}

func (p Persister) GetConsentRequest(ctx context.Context, challenge string) (*consent.OAuth2ConsentRequest, error) {
	return p.sqlPersister.GetConsentRequest(ctx, challenge)
}

func (p Persister) HandleConsentRequest(ctx context.Context, r *consent.AcceptOAuth2ConsentRequest) (*consent.OAuth2ConsentRequest, error) {
	return p.sqlPersister.HandleConsentRequest(ctx, r)
}

func (p Persister) RevokeSubjectConsentSession(ctx context.Context, user string) error {
	return p.sqlPersister.RevokeSubjectConsentSession(ctx, user)
}

func (p Persister) RevokeSubjectClientConsentSession(ctx context.Context, user, client string) error {
	return p.sqlPersister.RevokeSubjectClientConsentSession(ctx, user, client)
}

func (p Persister) VerifyAndInvalidateConsentRequest(ctx context.Context, verifier string) (*consent.AcceptOAuth2ConsentRequest, error) {
	return p.sqlPersister.VerifyAndInvalidateConsentRequest(ctx, verifier)
}

func (p Persister) FindGrantedAndRememberedConsentRequests(ctx context.Context, client, user string) ([]consent.AcceptOAuth2ConsentRequest, error) {
	return p.sqlPersister.FindGrantedAndRememberedConsentRequests(ctx, client, user)
}

func (p Persister) FindSubjectsGrantedConsentRequests(ctx context.Context, user string, limit, offset int) ([]consent.AcceptOAuth2ConsentRequest, error) {
	return p.sqlPersister.FindSubjectsGrantedConsentRequests(ctx, user, limit, offset)
}

func (p Persister) FindSubjectsSessionGrantedConsentRequests(ctx context.Context, user, sid string, limit, offset int) ([]consent.AcceptOAuth2ConsentRequest, error) {
	return p.sqlPersister.FindSubjectsSessionGrantedConsentRequests(ctx, user, sid, limit, offset)
}

func (p Persister) CountSubjectsGrantedConsentRequests(ctx context.Context, user string) (int, error) {
	return p.sqlPersister.CountSubjectsGrantedConsentRequests(ctx, user)
}

func (p Persister) GetRememberedLoginSession(ctx context.Context, id string) (*consent.LoginSession, error) {
	return p.sqlPersister.GetRememberedLoginSession(ctx, id)
}

func (p Persister) CreateLoginSession(ctx context.Context, session *consent.LoginSession) error {
	return p.sqlPersister.CreateLoginSession(ctx, session)
}

func (p Persister) DeleteLoginSession(ctx context.Context, id string) error {
	return p.sqlPersister.DeleteLoginSession(ctx, id)
}

func (p Persister) RevokeSubjectLoginSession(ctx context.Context, user string) error {
	return p.sqlPersister.RevokeSubjectLoginSession(ctx, user)
}

func (p Persister) ConfirmLoginSession(ctx context.Context, id string, authTime time.Time, subject string, remember bool) error {
	return p.sqlPersister.ConfirmLoginSession(ctx, id, authTime, subject, remember)
}

func (p Persister) CreateLoginRequest(ctx context.Context, req *consent.LoginRequest) error {
	return p.sqlPersister.CreateLoginRequest(ctx, req)
}

func (p Persister) GetLoginRequest(ctx context.Context, challenge string) (*consent.LoginRequest, error) {
	return p.sqlPersister.GetLoginRequest(ctx, challenge)
}

func (p Persister) HandleLoginRequest(ctx context.Context, challenge string, r *consent.HandledLoginRequest) (*consent.LoginRequest, error) {
	return p.sqlPersister.HandleLoginRequest(ctx, challenge, r)
}

func (p Persister) VerifyAndInvalidateLoginRequest(ctx context.Context, verifier string) (*consent.HandledLoginRequest, error) {
	return p.sqlPersister.VerifyAndInvalidateLoginRequest(ctx, verifier)
}

func (p Persister) FlushInactiveLoginConsentRequests(ctx context.Context, notAfter time.Time, limit int, batchSize int) error {
	return p.sqlPersister.FlushInactiveLoginConsentRequests(ctx, notAfter, limit, batchSize)
}
func (p Persister) CreateForcedObfuscatedLoginSession(ctx context.Context, session *consent.ForcedObfuscatedLoginSession) error {
	return p.sqlPersister.CreateForcedObfuscatedLoginSession(ctx, session)
}

func (p Persister) GetForcedObfuscatedLoginSession(ctx context.Context, client, obfuscated string) (*consent.ForcedObfuscatedLoginSession, error) {
	return p.sqlPersister.GetForcedObfuscatedLoginSession(ctx, client, obfuscated)
}

func (p Persister) ListUserAuthenticatedClientsWithFrontChannelLogout(ctx context.Context, subject, sid string) ([]client.Client, error) {
	return p.sqlPersister.ListUserAuthenticatedClientsWithFrontChannelLogout(ctx, subject, sid)
}

func (p Persister) ListUserAuthenticatedClientsWithBackChannelLogout(ctx context.Context, subject, sid string) ([]client.Client, error) {
	return p.sqlPersister.ListUserAuthenticatedClientsWithBackChannelLogout(ctx, subject, sid)
}

func (p Persister) CreateLogoutRequest(ctx context.Context, request *consent.LogoutRequest) error {
	return p.sqlPersister.CreateLogoutRequest(ctx, request)
}

func (p Persister) GetLogoutRequest(ctx context.Context, challenge string) (*consent.LogoutRequest, error) {
	return p.sqlPersister.GetLogoutRequest(ctx, challenge)
}

func (p Persister) AcceptLogoutRequest(ctx context.Context, challenge string) (*consent.LogoutRequest, error) {
	return p.sqlPersister.AcceptLogoutRequest(ctx, challenge)
}

func (p Persister) RejectLogoutRequest(ctx context.Context, challenge string) error {
	return p.sqlPersister.RejectLogoutRequest(ctx, challenge)
}

func (p Persister) VerifyAndInvalidateLogoutRequest(ctx context.Context, verifier string) (*consent.LogoutRequest, error) {
	return p.sqlPersister.VerifyAndInvalidateLogoutRequest(ctx, verifier)
}
