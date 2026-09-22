using System;

namespace Authio
{
    /// <summary>
    /// Failure from configuration, the network, or an Authio error body.
    /// <see cref="Code"/> matches the server's <c>code</c> field when the
    /// response was JSON.
    /// </summary>
    public class AuthioException : Exception
    {
        public string Code { get; }
        public int Status { get; }

        public AuthioException(string message, string code, int status = 0, Exception inner = null)
            : base(message, inner)
        {
            Code = string.IsNullOrEmpty(code) ? "error" : code;
            Status = status;
        }
    }
}
