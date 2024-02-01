using FluentValidation;
using System;
using System.Text.Json.Serialization;

namespace Models.ServiceParameters
{
    public class ServiceInput
    {
        [JsonIgnore]
        public string PinFromToken { get; set; }

        [JsonIgnore]
        public string OrganizationNameFromToken { get; set; }

        [JsonIgnore]
        public string VoenFromToken { get; set; }

        [JsonIgnore]
        public string SunFromToken { get; set; }

        [JsonIgnore]
        public string FullNameFromToken { get; set; }

        [JsonIgnore]
        public string PositionFromToken { get; set; }

        [JsonIgnore]
        public DateTime ExpiresFromToken { get; set; }
    }

    public class ServiceInputValidator : AbstractValidator<ServiceInput>
    {
        public ServiceInputValidator() { }
    }
}
