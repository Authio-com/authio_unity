using System;
using System.Runtime.InteropServices;
using UnityEngine;

namespace Authio
{
    /// <summary>
    /// Default session and pending stores. On an iOS device the blob is in
    /// the Keychain. On an Android device it is AES-GCM under the Android
    /// Keystore. The editor and every other player fall back to PlayerPrefs.
    /// Call <see cref="AuthioDeepLink.Configure"/> to replace either store.
    /// </summary>
    public static class AuthioSecureStore
    {
        public static IAuthioSessionStore Session()
        {
            return new SecureSessionStore();
        }

        public static IAuthioPendingStore Pending()
        {
            return new SecurePendingStore();
        }

        const string SessionKey = "authio.session.v1";
        const string PendingKey = "authio.pending.v1";

        sealed class SecureSessionStore : IAuthioSessionStore
        {
            public AuthioSession Load()
            {
                var raw = SecureBlob.Get(SessionKey);
                if (string.IsNullOrEmpty(raw)) return null;
                try
                {
                    return AuthioJson.Deserialize<AuthioSession>(raw);
                }
                catch (AuthioException)
                {
                    SecureBlob.Delete(SessionKey);
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
                SecureBlob.Set(SessionKey, AuthioJson.Serialize(session));
            }

            public void Clear()
            {
                SecureBlob.Delete(SessionKey);
            }
        }

        sealed class SecurePendingStore : IAuthioPendingStore
        {
            public AuthioPending Load()
            {
                var raw = SecureBlob.Get(PendingKey);
                if (string.IsNullOrEmpty(raw)) return null;
                try
                {
                    return AuthioJson.Deserialize<AuthioPending>(raw);
                }
                catch (AuthioException)
                {
                    SecureBlob.Delete(PendingKey);
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
                SecureBlob.Set(PendingKey, AuthioJson.Serialize(pending));
            }

            public void Clear()
            {
                SecureBlob.Delete(PendingKey);
            }
        }
    }

    static class SecureBlob
    {
        public static string Get(string key)
        {
#if UNITY_IOS && !UNITY_EDITOR
            var ptr = AuthioKeychain_Get(key);
            if (ptr == IntPtr.Zero) return "";
            var value = Marshal.PtrToStringAnsi(ptr);
            AuthioKeychain_Free(ptr);
            return value ?? "";
#elif UNITY_ANDROID && !UNITY_EDITOR
            try
            {
                using (var cls = new AndroidJavaClass("com.authio.unity.AuthioKeystore"))
                {
                    return cls.CallStatic<string>("get", key) ?? "";
                }
            }
            catch (Exception)
            {
                return PlayerPrefs.GetString(key, "");
            }
#else
            return PlayerPrefs.GetString(key, "");
#endif
        }

        public static void Set(string key, string value)
        {
#if UNITY_IOS && !UNITY_EDITOR
            AuthioKeychain_Set(key, value);
#elif UNITY_ANDROID && !UNITY_EDITOR
            try
            {
                using (var cls = new AndroidJavaClass("com.authio.unity.AuthioKeystore"))
                {
                    cls.CallStatic("set", key, value);
                    return;
                }
            }
            catch (Exception)
            {
                PlayerPrefs.SetString(key, value);
                PlayerPrefs.Save();
            }
#else
            PlayerPrefs.SetString(key, value);
            PlayerPrefs.Save();
#endif
        }

        public static void Delete(string key)
        {
#if UNITY_IOS && !UNITY_EDITOR
            AuthioKeychain_Set(key, null);
#elif UNITY_ANDROID && !UNITY_EDITOR
            try
            {
                using (var cls = new AndroidJavaClass("com.authio.unity.AuthioKeystore"))
                {
                    cls.CallStatic("delete", key);
                    return;
                }
            }
            catch (Exception)
            {
                PlayerPrefs.DeleteKey(key);
                PlayerPrefs.Save();
            }
#else
            PlayerPrefs.DeleteKey(key);
            PlayerPrefs.Save();
#endif
        }

#if UNITY_IOS && !UNITY_EDITOR
        [DllImport("__Internal")]
        static extern IntPtr AuthioKeychain_Get(string key);

        [DllImport("__Internal")]
        static extern void AuthioKeychain_Set(string key, string value);

        [DllImport("__Internal")]
        static extern void AuthioKeychain_Free(IntPtr ptr);
#endif
    }
}
