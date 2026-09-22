using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine;
using UnityEngine.Networking;

namespace Authio
{
    /// <summary>
    /// <see cref="IAuthioTransport"/> on <see cref="UnityWebRequest"/>.
    /// Call from the Unity main thread. Unity 2021.3 or newer.
    /// Called by <see cref="AuthioUnity.Create"/>.
    /// </summary>
    public sealed class UnityWebRequestTransport : IAuthioTransport
    {
        public async Task<AuthioResponse> SendAsync(AuthioRequest request, CancellationToken cancellationToken)
        {
            if (request == null) throw new ArgumentNullException("request");
            using (var uwr = new UnityWebRequest(request.Url, request.Method))
            {
                if (request.Body != null)
                {
                    var bytes = Encoding.UTF8.GetBytes(request.Body);
                    uwr.uploadHandler = new UploadHandlerRaw(bytes);
                }
                uwr.downloadHandler = new DownloadHandlerBuffer();
                uwr.timeout = request.TimeoutSeconds > 0 ? request.TimeoutSeconds : 30;
                if (request.Headers != null)
                {
                    foreach (var header in request.Headers)
                    {
                        uwr.SetRequestHeader(header.Key, header.Value);
                    }
                }

                var op = uwr.SendWebRequest();
                while (!op.isDone)
                {
                    if (cancellationToken.IsCancellationRequested)
                    {
                        uwr.Abort();
                        throw new AuthioException("Request cancelled.", "network_error");
                    }
                    await Task.Yield();
                }

                if (uwr.result == UnityWebRequest.Result.ConnectionError)
                {
                    throw new AuthioException(
                        string.IsNullOrEmpty(uwr.error) ? "Network failure." : uwr.error,
                        "network_error");
                }

                var body = uwr.downloadHandler == null ? "" : uwr.downloadHandler.text;
                return new AuthioResponse
                {
                    StatusCode = (int)uwr.responseCode,
                    Body = body,
                };
            }
        }
    }

    public static class AuthioUnity
    {
        public static AuthioClient Create(string publishableKey, AuthioOptions options = null)
        {
            return new AuthioClient(publishableKey, options, new UnityWebRequestTransport());
        }

        /// <summary>
        /// Persist <paramref name="pending"/> then open the system browser.
        /// The process may be killed before the deep link returns.
        /// </summary>
        public static void OpenBrowser(AuthioPending pending, IAuthioPendingStore store)
        {
            if (pending == null || string.IsNullOrEmpty(pending.Url))
            {
                throw new AuthioException("OAuth URL is missing.", "config_error");
            }
            if (store == null) throw new ArgumentNullException("store");
            store.Save(pending);
            Application.OpenURL(pending.Url);
        }
    }
}
