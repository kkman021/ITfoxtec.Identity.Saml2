using System.ComponentModel.DataAnnotations;
using Newtonsoft.Json;

namespace TestIdPCore.Models
{
    public class SamlDownSequenceData
    {
        [Required]
        public string Issuer { get; set; }

        [Required]
        [JsonProperty(PropertyName = "i")]
        public string Id { get; set; }

        [MaxLength(2000)]
        [JsonProperty(PropertyName = "rs")]
        public string RelayState { get; set; }

        [Required]
        public string SessionId { get; set; }

    }
}
