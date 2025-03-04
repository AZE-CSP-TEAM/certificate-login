using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using SecurityManager.Models;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Schema;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityManager.Helpers
{
    public class TokenHelper : ITokenHelper
    {
        private readonly IConfiguration _configuration;
        private readonly string _secret;
        private readonly string _securityAlgorithm;

        public TokenHelper(IConfiguration configuration)
        {
            _configuration = configuration;

            var secval = Environment.GetEnvironmentVariable("Token__Secret");
            _secret = Environment.GetEnvironmentVariable("Token__Secret")?.Trim().Trim('"');
            _securityAlgorithm = Environment.GetEnvironmentVariable("Token__SecurityAlgorithm")?.Trim();
        }

        public string GenerateSecureSecret() => Convert.ToBase64String(new HMACSHA256().Key);

        public string GenerateToken(TokenInput input)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();            

            return tokenHandler.WriteToken(tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(input.Claims),
                Issuer = input.Issuer,
                Expires = DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_secret)),
                _securityAlgorithm),
                IssuedAt = DateTime.UtcNow
            }));
        }
    }
}
