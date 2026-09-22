using System;
using System.Collections.Generic;
using System.Globalization;
using Newtonsoft.Json;

namespace Authio
{
    /// <summary>
    /// Session envelope returned by magic-link, handoff exchange, refresh,
    /// and organization switch. Store this. Discard the previous one when
    /// a call returns a replacement.
    /// </summary>
    public sealed class AuthioSession
    {
        [JsonProperty("session_id")]
        public string SessionId { get; set; }

        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }

        /// <summary>RFC 3339 timestamp from auth-core.</summary>
        [JsonProperty("expires_at")]
        public string ExpiresAt { get; set; }

        [JsonProperty("user")]
        public AuthioUser User { get; set; }

        [JsonProperty("active_organization")]
        public AuthioOrganization ActiveOrganization { get; set; }

        [JsonProperty("active_role")]
        public string ActiveRole { get; set; }

        [JsonProperty("memberships")]
        public List<AuthioMembership> Memberships { get; set; }

        public string UserId
        {
            get { return User == null ? "" : User.Id ?? ""; }
        }

        public string OrgId
        {
            get { return ActiveOrganization == null ? null : ActiveOrganization.Id; }
        }

        /// <summary>
        /// True when <see cref="ExpiresAt"/> parses and is not in the future.
        /// An unparseable value is treated as still current so a clock-format
        /// mismatch does not force a refresh loop; the server remains the
        /// authority via <see cref="AuthioClient.VerifyAsync"/>.
        /// </summary>
        public bool IsExpired
        {
            get
            {
                DateTime parsed;
                if (string.IsNullOrEmpty(ExpiresAt)) return false;
                if (!DateTime.TryParse(
                        ExpiresAt,
                        CultureInfo.InvariantCulture,
                        DateTimeStyles.RoundtripKind,
                        out parsed))
                {
                    return false;
                }
                return parsed.ToUniversalTime() <= DateTime.UtcNow;
            }
        }
    }

    public sealed class AuthioUser
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("project_id")]
        public string ProjectId { get; set; }

        [JsonProperty("email")]
        public string Email { get; set; }

        [JsonProperty("email_verified")]
        public bool EmailVerified { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("avatar_url")]
        public string AvatarUrl { get; set; }
    }

    public sealed class AuthioOrganization
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("project_id")]
        public string ProjectId { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("slug")]
        public string Slug { get; set; }
    }

    /// <summary>
    /// One row of <c>GET /v1/me/organizations</c>. Status is the raw server
    /// string (<c>active</c>, <c>invited</c>, <c>suspended</c>, <c>deactivated</c>).
    /// </summary>
    public sealed class AuthioMembership
    {
        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("project_id")]
        public string ProjectId { get; set; }

        [JsonProperty("user_id")]
        public string UserId { get; set; }

        [JsonProperty("organization_id")]
        public string OrganizationId { get; set; }

        [JsonProperty("role")]
        public string Role { get; set; }

        [JsonProperty("status")]
        public string Status { get; set; }

        [JsonProperty("organization")]
        public AuthioOrganization Organization { get; set; }
    }

    /// <summary>
    /// What to hold between opening the system browser and the deep link
    /// coming back. Persist it: mobile players leave the process.
    /// </summary>
    public sealed class AuthioPending
    {
        public string RedirectUri { get; set; }

        /// <summary>Login-CSRF nonce. Must match the callback query.</summary>
        public string ClientStateNonce { get; set; }

        /// <summary>Optional caller state, echoed as <c>state</c>.</summary>
        public string State { get; set; }

        /// <summary>Authorize URL. Null for magic-link sends.</summary>
        public string Url { get; set; }
    }

    public static class AuthioProviders
    {
        public const string Google = "google";
        public const string Microsoft = "microsoft";
        public const string Apple = "apple";
        public const string GitHub = "github";
        public const string Slack = "slack";
        public const string GitLab = "gitlab";
        public const string LinkedIn = "linkedin";
    }
}
