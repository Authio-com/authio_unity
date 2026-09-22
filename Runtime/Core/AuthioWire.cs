using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace Authio
{
    public sealed class AuthioOptions
    {
        /// <summary>
        /// Auth-core origin. Production is <c>https://identity.authio.com</c>
        /// (<c>https://auth-api.authio.com</c> redirects there). This is not
        /// the management API at <c>https://api.authio.com</c>.
        /// </summary>
        public string ApiUrl { get; set; } = AuthioClient.DefaultApiUrl;

        /// <summary>
        /// Tenant id (<c>proj_…</c>). Sent as <c>X-Authio-Project</c> on every
        /// call. Required: auth-core rejects requests that do not resolve a project.
        /// </summary>
        public string ProjectId { get; set; }

        public int TimeoutSeconds { get; set; } = 30;
    }

    public sealed class AuthioRequest
    {
        public string Method;
        public string Url;
        public string Body;
        public Dictionary<string, string> Headers;
        public int TimeoutSeconds;
    }

    public sealed class AuthioResponse
    {
        public int StatusCode;
        public string Body;
    }

    /// <summary>
    /// HTTP seam. The Unity package supplies <c>UnityWebRequest</c>. Tests
    /// supply a fake. Must be safe to call from the Unity main thread.
    /// </summary>
    public interface IAuthioTransport
    {
        Task<AuthioResponse> SendAsync(AuthioRequest request, CancellationToken cancellationToken);
    }

    public interface IAuthioSessionStore
    {
        AuthioSession Load();
        void Save(AuthioSession session);
        void Clear();
    }

    public interface IAuthioPendingStore
    {
        AuthioPending Load();
        void Save(AuthioPending pending);
        void Clear();
    }

    public sealed class MemorySessionStore : IAuthioSessionStore
    {
        AuthioSession _session;

        public AuthioSession Load() { return _session; }

        public void Save(AuthioSession session) { _session = session; }

        public void Clear() { _session = null; }
    }

    public sealed class MemoryPendingStore : IAuthioPendingStore
    {
        AuthioPending _pending;

        public AuthioPending Load() { return _pending; }

        public void Save(AuthioPending pending) { _pending = pending; }

        public void Clear() { _pending = null; }
    }

    internal static class AuthioNonce
    {
        public static string New()
        {
            var bytes = new byte[32];
            RandomNumberGenerator.Fill(bytes);
            var s = Convert.ToBase64String(bytes);
            return s.TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        public static bool EqualsConstantTime(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            var diff = 0;
            for (var i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }
            return diff == 0;
        }
    }
}
