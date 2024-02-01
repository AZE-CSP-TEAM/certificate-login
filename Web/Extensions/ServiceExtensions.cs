using Microsoft.AspNetCore.Http;
using Models.ServiceParameters;
using System;
using System.Linq;
using System.Security.Claims;

namespace Web.Extensions
{
    public static class ServiceExtensions
    {
        public static TInput Authorized<TInput>(this TInput input, HttpContext context) where TInput : ServiceInput, new()
        {
            TInput parameter = input ?? new TInput();
            try
            {
                parameter.PinFromToken = context.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
                parameter.VoenFromToken = context.User.Claims.FirstOrDefault(c => c.Type == "Voen")?.Value;
                parameter.SunFromToken = context.User.Claims.FirstOrDefault(c => c.Type == "Sun")?.Value;
                parameter.PositionFromToken = context.User.Claims.FirstOrDefault(c => c.Type == "Position")?.Value;
                parameter.FullNameFromToken = context.User.Claims.FirstOrDefault(c => c.Type == "FullName")?.Value;
                parameter.OrganizationNameFromToken = context.User.Claims.FirstOrDefault(c => c.Type == "OrganizationName")?.Value;
                parameter.ExpiresFromToken = DateTimeOffset.FromUnixTimeSeconds(
                    Convert.ToInt64(context.User.Claims.FirstOrDefault(c => c.Type == "exp")?.Value)).DateTime;
            }
            catch { }
            return parameter;
        }
    }
}
