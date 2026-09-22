using UnityEngine;

namespace Authio
{
    /// <summary>
    /// PlayerPrefs is not a keychain. Access tokens are short-lived; the
    /// refresh token sitting here is readable on a rooted device. A game
    /// that needs stronger storage can implement <see cref="IAuthioSessionStore"/>
    /// itself. Called by <see cref="AuthioDeepLink"/>.
    ///
    /// Stored JSON uses the session wire shape: session_id, access_token,
    /// refresh_token, expires_at (RFC 3339), user, active_organization,
    /// active_role, memberships. Pending JSON: redirect_uri, client_state_nonce,
    /// state, url. Keys are authio.session.v1 and authio.pending.v1.
    /// </summary>
    public sealed class PlayerPrefsSessionStore : IAuthioSessionStore
    {
        const string Key = "authio.session.v1";

        public AuthioSession Load()
        {
            var raw = PlayerPrefs.GetString(Key, "");
            if (string.IsNullOrEmpty(raw)) return null;
            try
            {
                return AuthioJson.Deserialize<AuthioSession>(raw);
            }
            catch (AuthioException)
            {
                PlayerPrefs.DeleteKey(Key);
                return null;
            }
        }

        public void Save(AuthioSession session)
        {
            if (session == null)
            {
                Clear();
                return;
            }
            PlayerPrefs.SetString(Key, AuthioJson.Serialize(session));
            PlayerPrefs.Save();
        }

        public void Clear()
        {
            PlayerPrefs.DeleteKey(Key);
            PlayerPrefs.Save();
        }
    }

    public sealed class PlayerPrefsPendingStore : IAuthioPendingStore
    {
        const string Key = "authio.pending.v1";

        public AuthioPending Load()
        {
            var raw = PlayerPrefs.GetString(Key, "");
            if (string.IsNullOrEmpty(raw)) return null;
            try
            {
                return AuthioJson.Deserialize<AuthioPending>(raw);
            }
            catch (AuthioException)
            {
                PlayerPrefs.DeleteKey(Key);
                return null;
            }
        }

        public void Save(AuthioPending pending)
        {
            if (pending == null)
            {
                Clear();
                return;
            }
            PlayerPrefs.SetString(Key, AuthioJson.Serialize(pending));
            PlayerPrefs.Save();
        }

        public void Clear()
        {
            PlayerPrefs.DeleteKey(Key);
            PlayerPrefs.Save();
        }
    }
}
