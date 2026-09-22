using System;
using System.Collections.Generic;
using System.Text;

namespace Authio
{
    public static class AuthioQuery
    {
        /// <summary>
        /// Query parameters from an http(s) URL or a custom-scheme deep link
        /// such as <c>mygame://auth?code=…</c>.
        /// </summary>
        public static Dictionary<string, string> Parse(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                throw new AuthioException("Callback URL is empty.", "invalid_callback_url");
            }

            string raw;
            try
            {
                var uri = new Uri(url);
                raw = JoinQueryAndFragment(uri.Query, uri.Fragment);
            }
            catch (UriFormatException)
            {
                raw = RawQueryOrFragment(url);
            }

            if (raw.StartsWith("?", StringComparison.Ordinal) || raw.StartsWith("#", StringComparison.Ordinal))
            {
                raw = raw.Substring(1);
            }

            var dict = new Dictionary<string, string>(StringComparer.Ordinal);
            if (raw.Length == 0) return dict;

            var pairs = raw.Split('&');
            for (var i = 0; i < pairs.Length; i++)
            {
                var pair = pairs[i];
                if (pair.Length == 0) continue;
                var idx = pair.IndexOf('=');
                var name = idx < 0 ? pair : pair.Substring(0, idx);
                var value = idx < 0 ? "" : pair.Substring(idx + 1);
                dict[Decode(name)] = Decode(value);
            }
            return dict;
        }

        public static string Append(string url, IDictionary<string, string> query)
        {
            if (query == null || query.Count == 0) return url;
            var sb = new StringBuilder(url);
            var first = url.IndexOf('?') < 0;
            foreach (var pair in query)
            {
                if (string.IsNullOrEmpty(pair.Value)) continue;
                sb.Append(first ? '?' : '&');
                first = false;
                sb.Append(Uri.EscapeDataString(pair.Key));
                sb.Append('=');
                sb.Append(Uri.EscapeDataString(pair.Value));
            }
            return sb.ToString();
        }

        static string JoinQueryAndFragment(string query, string fragment)
        {
            var frag = fragment ?? "";
            if (frag.StartsWith("#", StringComparison.Ordinal)) frag = frag.Substring(1);
            if (frag.Length == 0) return query ?? "";
            if (string.IsNullOrEmpty(query) || query == "?") return "#" + frag;
            return query + "&" + frag;
        }

        static string RawQueryOrFragment(string url)
        {
            var q = url.IndexOf('?');
            var h = url.IndexOf('#');
            if (q < 0 && h < 0) return "";
            if (q < 0) return url.Substring(h);
            if (h < 0) return url.Substring(q);
            if (h < q) return url.Substring(h);
            return url.Substring(q, h - q) + "&" + url.Substring(h + 1);
        }

        static string Decode(string value)
        {
            return Uri.UnescapeDataString((value ?? "").Replace("+", " "));
        }
    }
}
