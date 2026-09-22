using UnityEngine;

namespace Authio.Samples
{
    /// <summary>
    /// Wire this to UI buttons. Register <c>mygame</c> as a URL scheme and
    /// add <c>mygame://auth</c> to the project's allowed redirect URIs.
    /// Calls <see cref="AuthioDeepLink"/>.
    /// </summary>
    public sealed class AuthioSignInSample : MonoBehaviour
    {
        public AuthioDeepLink authio;
        public string redirectUri = "mygame://auth";
        public string email;

        void OnEnable()
        {
            if (authio != null) authio.SignedIn += OnSignedIn;
        }

        void OnDisable()
        {
            if (authio != null) authio.SignedIn -= OnSignedIn;
        }

        public void SendMagicLink()
        {
            if (authio == null) return;
            _ = authio.SendMagicLinkAsync(email, redirectUri);
        }

        public void SignInWithGoogle()
        {
            if (authio == null) return;
            authio.BeginOAuth(AuthioProviders.Google, redirectUri);
        }

        public void SignOut()
        {
            if (authio == null) return;
            _ = authio.SignOutAsync();
        }

        void OnSignedIn(AuthioSession session)
        {
            Debug.Log("Signed in as " + session.UserId + " org=" + (session.OrgId ?? "(none)"));
        }
    }
}
