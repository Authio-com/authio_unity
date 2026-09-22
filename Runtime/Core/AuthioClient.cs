using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Authio
{
    /// <summary>
    /// Player-facing Authio client for Unity and other .NET Standard 2.1 hosts.
    /// Embed a publishable key (<c>pk_live_</c> / <c>pk_test_</c>) only. Never
    /// put a secret key (<c>sk_</c>) in a game binary. Server-side user
    /// management belongs in the <c>Authio.Sdk</c> NuGet package.
    /// </summary>
    public sealed class AuthioClient
    {
        public const string Version = "0.1.0";
        public const string DefaultApiUrl = "https://identity.authio.com";

        static readonly Regex ProviderPattern = new Regex(
            "^[a-z0-9][a-z0-9_-]{0,63}$",
            RegexOptions.CultureInvariant);

        readonly string _publishableKey;
        readonly string _apiUrl;
        readonly string _projectId;
        readonly int _timeoutSeconds;
        readonly IAuthioTransport _transport;

        public string PublishableKey { get { return _publishableKey; } }
        public string ApiUrl { get { return _apiUrl; } }
        public string ProjectId { get { return _projectId; } }

        public AuthioClient(string publishableKey, AuthioOptions options, IAuthioTransport transport)
        {
            if (transport == null) throw new ArgumentNullException("transport");
            if (string.IsNullOrWhiteSpace(publishableKey))
            {
                throw new AuthioException("publishableKey is required.", "config_error");
            }
            if (publishableKey.StartsWith("sk_", StringComparison.Ordinal))
            {
                throw new AuthioException(
                    "Refusing a secret key. Use the project's publishable key (pk_live_ or pk_test_).",
                    "config_error");
            }
            options = options ?? new AuthioOptions();
            if (string.IsNullOrWhiteSpace(options.ProjectId))
            {
                throw new AuthioException(
                    "projectId is required. Authio rejects calls that do not name a project.",
                    "config_error");
            }
            if (options.TimeoutSeconds <= 0)
            {
                throw new AuthioException("timeoutSeconds must be positive.", "config_error");
            }

            _publishableKey = publishableKey.Trim();
            _apiUrl = NormalizeUrl(options.ApiUrl);
            _projectId = options.ProjectId.Trim();
            _timeoutSeconds = options.TimeoutSeconds;
            _transport = transport;
        }

        /// <summary>
        /// Email or E.164 phone. The message links back to <paramref name="redirectUri"/>
        /// (a custom scheme such as <c>mygame://auth</c>, registered on the project).
        /// Returns the pending values to persist before the player leaves the app.
        /// </summary>
        public async Task<AuthioPending> SendMagicLinkAsync(
            string destination,
            string redirectUri,
            string organizationId = null,
            string state = null,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            if (string.IsNullOrWhiteSpace(destination))
            {
                throw new AuthioException("destination is required.", "config_error");
            }
            redirectUri = RequireRedirect(redirectUri);
            var pending = new AuthioPending
            {
                RedirectUri = redirectUri,
                ClientStateNonce = AuthioNonce.New(),
                State = string.IsNullOrEmpty(state) ? null : state,
            };
            var body = new Dictionary<string, string>
            {
                { "destination", destination.Trim() },
                { "redirect_uri", redirectUri },
                { "client_state_nonce", pending.ClientStateNonce },
            };
            if (!string.IsNullOrEmpty(organizationId)) body["organization_id"] = organizationId;
            await SendAsync("POST", "/v1/auth/magic-link/send", AuthioJson.Serialize(body), null, null, cancellationToken).ConfigureAwait(false);
            return pending;
        }

        /// <summary>
        /// POST the one-time <paramref name="token"/> from a magic-link deep link.
        /// Prefer <see cref="CompleteCallbackAsync"/> — production browser
        /// redirects now carry a handoff <c>code</c>, not the raw token.
        /// </summary>
        public Task<AuthioSession> ConsumeMagicLinkAsync(
            string token,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                throw new AuthioException("Magic-link token is missing.", "invalid_callback_url");
            }
            var query = new Dictionary<string, string> { { "token", token.Trim() } };
            return SendSessionAsync("POST", "/v1/auth/magic-link/callback", "{}", null, query, cancellationToken);
        }

        /// <summary>
        /// Browser URL for <c>GET /v1/auth/oauth/{provider}/authorize</c>.
        /// The game cannot attach headers to <c>Application.OpenURL</c>, so
        /// the project id is also a query parameter. Persist the returned
        /// pending value before opening the URL.
        /// </summary>
        public AuthioPending BuildOAuthAuthorizeUrl(
            string provider,
            string redirectUri,
            string organizationId = null,
            string state = null)
        {
            if (string.IsNullOrWhiteSpace(provider) || !ProviderPattern.IsMatch(provider))
            {
                throw new AuthioException("OAuth provider id is not valid.", "config_error");
            }
            redirectUri = RequireRedirect(redirectUri);
            var pending = new AuthioPending
            {
                RedirectUri = redirectUri,
                ClientStateNonce = AuthioNonce.New(),
                State = string.IsNullOrEmpty(state) ? null : state,
            };
            var query = new Dictionary<string, string>
            {
                { "redirect_uri", redirectUri },
                { "project_id", _projectId },
                { "client_state_nonce", pending.ClientStateNonce },
            };
            if (!string.IsNullOrEmpty(organizationId)) query["organization_id"] = organizationId;
            if (!string.IsNullOrEmpty(pending.State)) query["signin_state"] = pending.State;
            pending.Url = AuthioQuery.Append(
                _apiUrl + "/v1/auth/oauth/" + provider + "/authorize",
                query);
            return pending;
        }

        /// <summary>
        /// Finish a deep link. Handles a session-handoff <c>code</c> (current
        /// browser redirect), a magic-link <c>token</c>, or a legacy
        /// <c>access_token</c> query. <paramref name="pending"/> is the value
        /// returned when the flow started; it supplies the registered redirect
        /// URI and the nonce check.
        /// </summary>
        public async Task<AuthioSession> CompleteCallbackAsync(
            string callbackUrl,
            AuthioPending pending,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            var query = AuthioQuery.Parse(callbackUrl);
            string error;
            if (query.TryGetValue("error", out error) && !string.IsNullOrEmpty(error))
            {
                string description;
                query.TryGetValue("error_description", out description);
                throw new AuthioException(
                    string.IsNullOrEmpty(description) ? error : description,
                    "oauth." + error);
            }

            if (pending != null && !string.IsNullOrEmpty(pending.State))
            {
                string got;
                query.TryGetValue("state", out got);
                if (!string.Equals(got, pending.State, StringComparison.Ordinal))
                {
                    throw new AuthioException("Sign-in state did not match.", "state_mismatch");
                }
            }

            string token;
            string code;
            if (query.TryGetValue("token", out token) && !string.IsNullOrEmpty(token)
                && !(query.TryGetValue("code", out code) && !string.IsNullOrEmpty(code)))
            {
                return await ConsumeMagicLinkAsync(token, cancellationToken).ConfigureAwait(false);
            }

            if (query.TryGetValue("code", out code) && !string.IsNullOrEmpty(code))
            {
                if (pending == null || string.IsNullOrEmpty(pending.RedirectUri))
                {
                    throw new AuthioException(
                        "The pending redirect URI is required to exchange this code.",
                        "invalid_callback_url");
                }
                string nonce;
                query.TryGetValue("client_state_nonce", out nonce);
                if (!string.IsNullOrEmpty(pending.ClientStateNonce)
                    && !AuthioNonce.EqualsConstantTime(pending.ClientStateNonce, nonce ?? ""))
                {
                    throw new AuthioException("Sign-in nonce did not match.", "invalid_handoff");
                }
                var echoed = string.IsNullOrEmpty(nonce) ? pending.ClientStateNonce : nonce;
                return await ExchangeHandoffAsync(code, pending.RedirectUri, echoed, cancellationToken).ConfigureAwait(false);
            }

            string access;
            string sessionId;
            if (query.TryGetValue("access_token", out access) && query.TryGetValue("session_id", out sessionId)
                && !string.IsNullOrEmpty(access) && !string.IsNullOrEmpty(sessionId))
            {
                string refresh;
                string expires;
                query.TryGetValue("refresh_token", out refresh);
                query.TryGetValue("expires_at", out expires);
                return new AuthioSession
                {
                    SessionId = sessionId,
                    AccessToken = access,
                    RefreshToken = refresh,
                    ExpiresAt = expires ?? "",
                };
            }

            throw new AuthioException(
                "Callback URL has no code, token, or session.",
                "invalid_callback_url");
        }

        public Task<AuthioSession> ExchangeHandoffAsync(
            string code,
            string redirectUri,
            string clientStateNonce,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            if (string.IsNullOrWhiteSpace(code))
            {
                throw new AuthioException("Handoff code is missing.", "invalid_handoff");
            }
            redirectUri = RequireRedirect(redirectUri);
            if (string.IsNullOrEmpty(clientStateNonce))
            {
                throw new AuthioException("client_state_nonce is required.", "invalid_handoff");
            }
            var body = new Dictionary<string, string>
            {
                { "code", code.Trim() },
                { "redirect_uri", redirectUri },
                { "client_state_nonce", clientStateNonce },
            };
            return SendSessionAsync(
                "POST",
                "/v1/auth/session-handoff/exchange",
                AuthioJson.Serialize(body),
                null,
                null,
                cancellationToken);
        }

        /// <summary>
        /// True when <c>GET /v1/me</c> accepts the access token. A locally
        /// expired token returns false without a request. 401 and 403 are
        /// false. Other HTTP errors throw.
        /// </summary>
        public async Task<bool> VerifyAsync(
            AuthioSession session,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            if (session == null || string.IsNullOrEmpty(session.AccessToken)) return false;
            if (session.IsExpired) return false;
            try
            {
                await MeAsync(session, cancellationToken).ConfigureAwait(false);
                return true;
            }
            catch (AuthioException ex)
            {
                if (ex.Status == 401 || ex.Status == 403) return false;
                throw;
            }
        }

        public async Task<AuthioUser> MeAsync(
            AuthioSession session,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            var json = await SendAsync("GET", "/v1/me", null, RequireAccess(session), null, cancellationToken).ConfigureAwait(false);
            return AuthioJson.Deserialize<AuthioUser>(json);
        }

        public async Task<List<AuthioMembership>> ListOrganizationsAsync(
            AuthioSession session,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            var json = await SendAsync(
                "GET",
                "/v1/me/organizations",
                null,
                RequireAccess(session),
                null,
                cancellationToken).ConfigureAwait(false);
            if (string.IsNullOrEmpty(json)) return new List<AuthioMembership>();
            return AuthioJson.Deserialize<List<AuthioMembership>>(json);
        }

        public Task<AuthioSession> SelectOrganizationAsync(
            AuthioSession session,
            string organizationId,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            return OrgAsync(session, "/v1/sessions/select-org", organizationId, cancellationToken);
        }

        public Task<AuthioSession> SwitchOrganizationAsync(
            AuthioSession session,
            string organizationId,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            return OrgAsync(session, "/v1/sessions/switch-org", organizationId, cancellationToken);
        }

        public async Task<AuthioSession> RefreshAsync(
            AuthioSession session,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            if (session == null || string.IsNullOrEmpty(session.RefreshToken))
            {
                throw new AuthioException("refresh token is missing.", "config_error");
            }
            var body = AuthioJson.Serialize(new Dictionary<string, string>
            {
                { "refresh_token", session.RefreshToken },
            });
            return await SendSessionAsync("POST", "/v1/auth/refresh", body, null, null, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Returns <paramref name="session"/> when the access token is still
        /// inside its expiry, otherwise rotates via the refresh token.
        /// </summary>
        public Task<AuthioSession> EnsureFreshAsync(
            AuthioSession session,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            if (session == null) throw new AuthioException("session is required.", "config_error");
            if (!session.IsExpired && !string.IsNullOrEmpty(session.AccessToken))
            {
                return Task.FromResult(session);
            }
            return RefreshAsync(session, cancellationToken);
        }

        public async Task RevokeAsync(
            AuthioSession session,
            CancellationToken cancellationToken = default(CancellationToken))
        {
            var body = AuthioJson.Serialize(new Dictionary<string, string>
            {
                { "session_id", session == null ? "" : session.SessionId ?? "" },
            });
            await SendAsync("POST", "/v1/sessions/revoke", body, RequireAccess(session), null, cancellationToken).ConfigureAwait(false);
        }

        Task<AuthioSession> OrgAsync(
            AuthioSession session,
            string path,
            string organizationId,
            CancellationToken cancellationToken)
        {
            if (string.IsNullOrWhiteSpace(organizationId))
            {
                throw new AuthioException("organizationId is required.", "config_error");
            }
            var body = AuthioJson.Serialize(new Dictionary<string, string>
            {
                { "organization_id", organizationId.Trim() },
            });
            return SendSessionAsync("POST", path, body, RequireAccess(session), null, cancellationToken);
        }

        async Task<AuthioSession> SendSessionAsync(
            string method,
            string path,
            string body,
            string bearer,
            Dictionary<string, string> query,
            CancellationToken cancellationToken)
        {
            var json = await SendAsync(method, path, body, bearer, query, cancellationToken).ConfigureAwait(false);
            var session = AuthioJson.Deserialize<AuthioSession>(json);
            if (session.Memberships == null) session.Memberships = new List<AuthioMembership>();
            if (string.IsNullOrEmpty(session.AccessToken) || string.IsNullOrEmpty(session.SessionId))
            {
                throw new AuthioException("Session response was missing tokens.", "decode_error");
            }
            return session;
        }

        async Task<string> SendAsync(
            string method,
            string path,
            string body,
            string bearer,
            Dictionary<string, string> query,
            CancellationToken cancellationToken)
        {
            var url = AuthioQuery.Append(_apiUrl + path, query);
            var headers = new Dictionary<string, string>
            {
                { "Authorization", "Bearer " + (string.IsNullOrEmpty(bearer) ? _publishableKey : bearer) },
                { "X-Authio-Publishable-Key", _publishableKey },
                { "X-Authio-Project", _projectId },
                { "Accept", "application/json" },
                { "User-Agent", "authio-unity/" + Version },
                { "X-Authio-SDK", "unity/" + Version },
            };
            if (body != null)
            {
                headers["Content-Type"] = "application/json";
            }

            AuthioResponse response;
            try
            {
                response = await _transport.SendAsync(new AuthioRequest
                {
                    Method = method,
                    Url = url,
                    Body = body,
                    Headers = headers,
                    TimeoutSeconds = _timeoutSeconds,
                }, cancellationToken).ConfigureAwait(false);
            }
            catch (AuthioException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new AuthioException("Network failure.", "network_error", 0, ex);
            }

            if (response == null)
            {
                throw new AuthioException("Transport returned no response.", "network_error");
            }
            if (response.StatusCode >= 200 && response.StatusCode < 300)
            {
                return response.Body ?? "";
            }

            string code = "http_" + response.StatusCode;
            string message = "HTTP " + response.StatusCode;
            if (!string.IsNullOrEmpty(response.Body))
            {
                try
                {
                    var err = AuthioJson.Deserialize<WireError>(response.Body);
                    if (!string.IsNullOrEmpty(err.Code)) code = err.Code;
                    if (!string.IsNullOrEmpty(err.Message)) message = err.Message;
                }
                catch (AuthioException)
                {
                    message = "HTTP " + response.StatusCode;
                }
            }
            throw new AuthioException(message, code, response.StatusCode);
        }

        static string RequireAccess(AuthioSession session)
        {
            if (session == null || string.IsNullOrEmpty(session.AccessToken))
            {
                throw new AuthioException("access token is required.", "config_error");
            }
            return session.AccessToken;
        }

        static string RequireRedirect(string redirectUri)
        {
            if (string.IsNullOrWhiteSpace(redirectUri))
            {
                throw new AuthioException("redirectUri is required.", "config_error");
            }
            return redirectUri.Trim();
        }

        static string NormalizeUrl(string apiUrl)
        {
            if (string.IsNullOrWhiteSpace(apiUrl))
            {
                throw new AuthioException("apiUrl is required.", "config_error");
            }
            var trimmed = apiUrl.Trim().TrimEnd('/');
            Uri parsed;
            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out parsed)
                || (parsed.Scheme != "https" && parsed.Scheme != "http"))
            {
                throw new AuthioException("apiUrl is not an http(s) URL.", "config_error");
            }
            return trimmed;
        }

        sealed class WireError
        {
            [Newtonsoft.Json.JsonProperty("code")]
            public string Code { get; set; }

            [Newtonsoft.Json.JsonProperty("message")]
            public string Message { get; set; }
        }
    }
}
