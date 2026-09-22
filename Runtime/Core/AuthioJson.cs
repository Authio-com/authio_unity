using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;

namespace Authio
{
    public static class AuthioJson
    {
        public static readonly JsonSerializerSettings Settings = new JsonSerializerSettings
        {
            NullValueHandling = NullValueHandling.Ignore,
            MissingMemberHandling = MissingMemberHandling.Ignore,
            ContractResolver = new DefaultContractResolver
            {
                NamingStrategy = new SnakeCaseNamingStrategy(),
            },
        };

        public static string Serialize(object value)
        {
            return JsonConvert.SerializeObject(value, Settings);
        }

        public static T Deserialize<T>(string json)
        {
            if (string.IsNullOrEmpty(json))
            {
                throw new AuthioException("Empty response body.", "decode_error");
            }
            try
            {
                var value = JsonConvert.DeserializeObject<T>(json, Settings);
                if (value == null)
                {
                    throw new AuthioException("Response decoded to null.", "decode_error");
                }
                return value;
            }
            catch (AuthioException)
            {
                throw;
            }
            catch (JsonException ex)
            {
                throw new AuthioException("Response was not the expected JSON.", "decode_error", 0, ex);
            }
        }
    }
}
