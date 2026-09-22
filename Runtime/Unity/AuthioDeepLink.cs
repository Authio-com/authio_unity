using System;
using System.Threading.Tasks;
using UnityEngine;

namespace Authio
{
    /// <summary>
    /// Completes <c>Application.deepLinkActivated</c> against the pending
    /// sign-in saved before the browser opened. Put one instance in the
    /// first scene. The game scene calls <see cref="BeginOAuth"/> and
    /// <see cref="SendMagicLinkAsync"/>.
    /// </summary>
    [DefaultExecutionOrder(100)]
    public sealed class AuthioDeepLink : MonoBehaviour
    {
        public AuthioConfig config;

        public event Action<AuthioSession> SignedIn;
        public event Action<Exception> Failed;

        AuthioClient _client;
        IAuthioSessionStore _sessions;
        IAuthioPendingStore _pending;

        /// <summary>
        /// Supplies the stores before Awake. A game script at the default
        /// execution order can call this from its own Awake. Null arguments
        /// are left unchanged.
        /// </summary>
        public void Configure(IAuthioSessionStore sessions, IAuthioPendingStore pending)
        {
            if (sessions != null) _sessions = sessions;
            if (pending != null) _pending = pending;
        }

        void Awake()
        {
            if (config == null)
            {
                Debug.LogError("AuthioDeepLink has no AuthioConfig.");
                return;
            }
            _client = config.CreateClient();
            if (_sessions == null) _sessions = AuthioSecureStore.Session();
            if (_pending == null) _pending = AuthioSecureStore.Pending();
        }

        void OnEnable()
        {
            Application.deepLinkActivated += OnDeepLink;
            if (!string.IsNullOrEmpty(Application.absoluteURL))
            {
                OnDeepLink(Application.absoluteURL);
            }
        }

        void OnDisable()
        {
            Application.deepLinkActivated -= OnDeepLink;
        }

        void OnDeepLink(string url)
        {
            if (_client == null || string.IsNullOrEmpty(url)) return;
            if (url.IndexOf("code=", StringComparison.Ordinal) < 0
                && url.IndexOf("token=", StringComparison.Ordinal) < 0
                && url.IndexOf("access_token=", StringComparison.Ordinal) < 0
                && url.IndexOf("error=", StringComparison.Ordinal) < 0)
            {
                return;
            }
            Complete(url);
        }

        async void Complete(string url)
        {
            try
            {
                var session = await _client.CompleteCallbackAsync(url, _pending.Load());
                _pending.Clear();
                _sessions.Save(session);
                var handler = SignedIn;
                if (handler != null) handler(session);
            }
            catch (Exception ex)
            {
                Debug.LogWarning("Authio callback failed: " + ex.Message);
                var handler = Failed;
                if (handler != null) handler(ex);
            }
        }

        public AuthioSession LoadSession()
        {
            return _sessions == null ? null : _sessions.Load();
        }

        public Task<AuthioPending> SendMagicLinkAsync(string destination, string redirectUri, string organizationId = null)
        {
            var pending = _client.SendMagicLinkAsync(destination, redirectUri, organizationId);
            return SaveWhenReady(pending);
        }

        public AuthioPending BeginOAuth(string provider, string redirectUri, string organizationId = null)
        {
            var pending = _client.BuildOAuthAuthorizeUrl(provider, redirectUri, organizationId);
            AuthioUnity.OpenBrowser(pending, _pending);
            return pending;
        }

        public async Task SignOutAsync()
        {
            var session = _sessions.Load();
            if (session != null)
            {
                try
                {
                    await _client.RevokeAsync(session);
                }
                catch (AuthioException ex)
                {
                    Debug.LogWarning("Authio revoke failed: " + ex.Message);
                }
            }
            _sessions.Clear();
            _pending.Clear();
        }

        async Task<AuthioPending> SaveWhenReady(Task<AuthioPending> pendingTask)
        {
            var pending = await pendingTask;
            _pending.Save(pending);
            return pending;
        }
    }
}
