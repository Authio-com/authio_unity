using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Authio;
using Xunit;

namespace Authio.Tests
{
    public sealed class ClientTests
    {
        const string Envelope =
            "{\"session_id\":\"ses_1\",\"access_token\":\"at_1\",\"refresh_token\":\"rt_1\"," +
            "\"expires_at\":\"2099-01-01T00:00:00Z\",\"user\":{\"id\":\"usr_1\",\"project_id\":\"proj_1\"," +
            "\"email\":\"a@example.com\",\"email_verified\":true,\"identities\":[]}," +
            "\"memberships\":[]}";

        [Fact]
        public void RejectsSecretKeyAndMissingProject()
        {
            var transport = new FakeTransport();
            var ex = Assert.Throws<AuthioException>(() => Client("sk_live_nope", "proj_1", transport));
            Assert.Equal("config_error", ex.Code);
            ex = Assert.Throws<AuthioException>(() => Client("pk_test_ok", "  ", transport));
            Assert.Equal("config_error", ex.Code);
        }

        [Fact]
        public async Task MagicLinkPostsProjectHeaderAndNonce()
        {
            var transport = new FakeTransport();
            transport.Enqueue(202, "");
            var client = Client("pk_test_ok", "proj_1", transport);
            var pending = await client.SendMagicLinkAsync("a@example.com", "mygame://auth", "org_1");
            var req = transport.Last;
            Assert.Equal("POST", req.Method);
            Assert.Equal("https://identity.authio.com/v1/auth/magic-link/send", req.Url);
            Assert.Contains("\"destination\":\"a@example.com\"", req.Body);
            Assert.Contains("\"redirect_uri\":\"mygame://auth\"", req.Body);
            Assert.Contains(pending.ClientStateNonce, req.Body);
            Assert.Contains("\"organization_id\":\"org_1\"", req.Body);
            Assert.DoesNotContain("session_id", req.Body);
            Assert.Equal("Bearer pk_test_ok", req.Headers["Authorization"]);
            Assert.Equal("proj_1", req.Headers["X-Authio-Project"]);
            Assert.Equal("unity/0.1.0", req.Headers["X-Authio-SDK"]);
            Assert.StartsWith("authio-unity/", req.Headers["User-Agent"]);
        }

        [Fact]
        public void OAuthUrlCarriesProjectBecauseTheBrowserCannot()
        {
            var client = Client("pk_test_ok", "proj_1", new FakeTransport());
            var pending = client.BuildOAuthAuthorizeUrl(AuthioProviders.Google, "mygame://auth", null, "state_1");
            Assert.StartsWith("https://identity.authio.com/v1/auth/oauth/google/authorize?", pending.Url);
            Assert.Contains("project_id=proj_1", pending.Url);
            Assert.Contains("redirect_uri=mygame%3A%2F%2Fauth", pending.Url);
            Assert.Contains("client_state_nonce=", pending.Url);
            Assert.Contains("signin_state=state_1", pending.Url);
            Assert.DoesNotContain("pk_test_ok", pending.Url);
        }

        [Fact]
        public async Task HandoffExchangeChecksNonceAndPostsRegisteredRedirect()
        {
            var transport = new FakeTransport();
            var client = Client("pk_test_ok", "proj_1", transport);
            var pending = new AuthioPending
            {
                RedirectUri = "mygame://auth",
                ClientStateNonce = "nonce_a",
                State = "state_1",
            };
            var mismatch = Assert.ThrowsAsync<AuthioException>(() =>
                client.CompleteCallbackAsync("mygame://auth?code=c1&client_state_nonce=nonce_b&state=state_1", pending));
            Assert.Equal("invalid_handoff", (await mismatch).Code);
            Assert.Empty(transport.Requests);

            transport.Enqueue(200, Envelope);
            var session = await client.CompleteCallbackAsync(
                "mygame://auth?code=c1&client_state_nonce=nonce_a&state=state_1",
                pending);
            Assert.Equal("ses_1", session.SessionId);
            Assert.Equal("POST", transport.Last.Method);
            Assert.Equal("https://identity.authio.com/v1/auth/session-handoff/exchange", transport.Last.Url);
            Assert.Contains("\"code\":\"c1\"", transport.Last.Body);
            Assert.Contains("\"redirect_uri\":\"mygame://auth\"", transport.Last.Body);
            Assert.Contains("\"client_state_nonce\":\"nonce_a\"", transport.Last.Body);
        }

        [Fact]
        public async Task StateMismatchDoesNotCallTheNetwork()
        {
            var transport = new FakeTransport();
            var client = Client("pk_test_ok", "proj_1", transport);
            var pending = new AuthioPending
            {
                RedirectUri = "mygame://auth",
                ClientStateNonce = "nonce_a",
                State = "expected",
            };
            var ex = await Assert.ThrowsAsync<AuthioException>(() =>
                client.CompleteCallbackAsync("mygame://auth?code=c1&client_state_nonce=nonce_a&state=other", pending));
            Assert.Equal("state_mismatch", ex.Code);
            Assert.Empty(transport.Requests);
        }

        [Fact]
        public async Task MagicLinkTokenCallbackPostsTheToken()
        {
            var transport = new FakeTransport();
            transport.Enqueue(200, Envelope);
            var client = Client("pk_test_ok", "proj_1", transport);
            var session = await client.CompleteCallbackAsync("mygame://auth?token=ml_1", null);
            Assert.Equal("usr_1", session.UserId);
            Assert.Equal("https://identity.authio.com/v1/auth/magic-link/callback?token=ml_1", transport.Last.Url);
            Assert.Equal("{}", transport.Last.Body);
        }

        [Fact]
        public async Task LegacyTokenQueryDoesNotHitTheNetwork()
        {
            var transport = new FakeTransport();
            var client = Client("pk_test_ok", "proj_1", transport);
            var session = await client.CompleteCallbackAsync(
                "mygame://auth?session_id=ses_9&access_token=at_9&refresh_token=rt_9&expires_at=2099-01-01T00%3A00%3A00Z",
                null);
            Assert.Equal("ses_9", session.SessionId);
            Assert.Equal("at_9", session.AccessToken);
            Assert.Equal("rt_9", session.RefreshToken);
            Assert.Empty(transport.Requests);
        }

        [Fact]
        public async Task VerifyTreats401AsSignedOutAnd500AsFailure()
        {
            var transport = new FakeTransport();
            transport.Enqueue(401, "{\"code\":\"no_session\",\"message\":\"no active session\"}");
            var client = Client("pk_test_ok", "proj_1", transport);
            var session = new AuthioSession { AccessToken = "at", ExpiresAt = "2099-01-01T00:00:00Z" };
            Assert.False(await client.VerifyAsync(session));
            Assert.Equal("Bearer at", transport.Last.Headers["Authorization"]);

            transport.Enqueue(500, "{\"code\":\"store_unavailable\",\"message\":\"down\"}");
            var ex = await Assert.ThrowsAsync<AuthioException>(() => client.VerifyAsync(session));
            Assert.Equal("store_unavailable", ex.Code);
            Assert.Equal(500, ex.Status);
        }

        [Fact]
        public async Task ExpiredSessionIsNotVerifiedOverTheNetwork()
        {
            var transport = new FakeTransport();
            var client = Client("pk_test_ok", "proj_1", transport);
            var session = new AuthioSession { AccessToken = "at", ExpiresAt = "2000-01-01T00:00:00Z" };
            Assert.True(session.IsExpired);
            Assert.False(await client.VerifyAsync(session));
            Assert.Empty(transport.Requests);
        }

        [Fact]
        public async Task RefreshAndOrgSwitchSendOnlyTheFieldsTheServerAllows()
        {
            var transport = new FakeTransport();
            transport.Enqueue(200, Envelope);
            var client = Client("pk_test_ok", "proj_1", transport);
            var session = new AuthioSession
            {
                SessionId = "ses_1",
                AccessToken = "at_1",
                RefreshToken = "rt_1",
                ExpiresAt = "2000-01-01T00:00:00Z",
            };
            await client.RefreshAsync(session);
            Assert.Equal("{\"refresh_token\":\"rt_1\"}", transport.Last.Body);
            Assert.Equal("https://identity.authio.com/v1/auth/refresh", transport.Last.Url);
            Assert.Equal("Bearer pk_test_ok", transport.Last.Headers["Authorization"]);

            transport.Enqueue(200, Envelope);
            await client.SelectOrganizationAsync(session, "org_9");
            Assert.Equal("{\"organization_id\":\"org_9\"}", transport.Last.Body);
            Assert.DoesNotContain("session_id", transport.Last.Body);
            Assert.Equal("Bearer at_1", transport.Last.Headers["Authorization"]);
            Assert.EndsWith("/v1/sessions/select-org", transport.Last.Url);
        }

        [Fact]
        public async Task RevokeIs204AndListsOrganizations()
        {
            var transport = new FakeTransport();
            transport.Enqueue(204, "");
            var client = Client("pk_test_ok", "proj_1", transport);
            var session = new AuthioSession { SessionId = "ses_1", AccessToken = "at_1", ExpiresAt = "2099-01-01T00:00:00Z" };
            await client.RevokeAsync(session);
            Assert.Contains("\"session_id\":\"ses_1\"", transport.Last.Body);

            transport.Enqueue(200,
                "[{\"id\":\"mem_1\",\"organization_id\":\"org_1\",\"role\":\"member\",\"status\":\"active\"," +
                "\"organization\":{\"id\":\"org_1\",\"name\":\"Acme\",\"slug\":\"acme\"}}]");
            var orgs = await client.ListOrganizationsAsync(session);
            Assert.Single(orgs);
            Assert.Equal("Acme", orgs[0].Organization.Name);
            Assert.Equal("active", orgs[0].Status);
        }

        [Fact]
        public void PendingAndSessionJsonRoundTripForPlayerPrefs()
        {
            var pending = new AuthioPending
            {
                RedirectUri = "mygame://auth",
                ClientStateNonce = "abc",
                State = "s",
                Url = "https://example.test/authorize",
            };
            var back = AuthioJson.Deserialize<AuthioPending>(AuthioJson.Serialize(pending));
            Assert.Equal("mygame://auth", back.RedirectUri);
            Assert.Equal("abc", back.ClientStateNonce);
            Assert.Equal("s", back.State);
            Assert.Equal("https://example.test/authorize", back.Url);

            var session = AuthioJson.Deserialize<AuthioSession>(Envelope);
            var again = AuthioJson.Deserialize<AuthioSession>(AuthioJson.Serialize(session));
            Assert.Equal("ses_1", again.SessionId);
            Assert.Equal("at_1", again.AccessToken);
            Assert.Equal("usr_1", again.UserId);
        }

        [Fact]
        public void CustomSchemeQueryRoundTrips()
        {
            var q = AuthioQuery.Parse("mygame://auth?code=abc&client_state_nonce=n+1");
            Assert.Equal("abc", q["code"]);
            Assert.Equal("n 1", q["client_state_nonce"]);
        }

        [Fact]
        public void OAuthErrorQueryThrows()
        {
            var client = Client("pk_test_ok", "proj_1", new FakeTransport());
            var ex = Assert.Throws<AuthioException>(() =>
                client.CompleteCallbackAsync("mygame://auth?error=access_denied&error_description=no", null).GetAwaiter().GetResult());
            Assert.Equal("oauth.access_denied", ex.Code);
            Assert.Equal("no", ex.Message);
        }

        sealed class FakeTransport : IAuthioTransport
        {
            readonly Queue<AuthioResponse> _responses = new Queue<AuthioResponse>();
            public List<AuthioRequest> Requests = new List<AuthioRequest>();
            public AuthioRequest Last;

            public void Enqueue(int status, string body)
            {
                _responses.Enqueue(new AuthioResponse { StatusCode = status, Body = body });
            }

            public Task<AuthioResponse> SendAsync(AuthioRequest request, CancellationToken cancellationToken)
            {
                Requests.Add(request);
                Last = request;
                if (_responses.Count == 0)
                {
                    throw new InvalidOperationException("no fake response queued");
                }
                return Task.FromResult(_responses.Dequeue());
            }
        }

        static AuthioClient Client(string key, string project, IAuthioTransport transport)
        {
            return new AuthioClient(key, new AuthioOptions { ProjectId = project }, transport);
        }
    }
}
