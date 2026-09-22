using UnityEngine;

namespace Authio
{
    /// <summary>
    /// Drop on a ScriptableObject asset: Assets → Create → Authio → Config.
    /// The publishable key and project id are public client identifiers.
    /// Called by <see cref="AuthioDeepLink"/>.
    /// </summary>
    [CreateAssetMenu(fileName = "AuthioConfig", menuName = "Authio/Config")]
    public sealed class AuthioConfig : ScriptableObject
    {
        public string publishableKey;
        public string projectId;
        public string apiUrl = AuthioClient.DefaultApiUrl;

        public AuthioClient CreateClient()
        {
            return AuthioUnity.Create(publishableKey, new AuthioOptions
            {
                ApiUrl = string.IsNullOrEmpty(apiUrl) ? AuthioClient.DefaultApiUrl : apiUrl,
                ProjectId = projectId,
            });
        }
    }
}
