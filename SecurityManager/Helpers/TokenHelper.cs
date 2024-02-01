using Microsoft.IdentityModel.Tokens;
using SecurityManager.Models;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace SecurityManager.Helpers
{
    public class TokenHelper : ITokenHelper
    {
        public string GenerateSecureSecret() => Convert.ToBase64String(new HMACSHA256().Key);

        public string GenerateToken(TokenInput input)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            return tokenHandler.WriteToken(tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(input.Claims),
                Issuer = input.Issuer,
                Audience = input.Customer.Audience,
                Expires = DateTime.UtcNow.AddMinutes(input.Customer.Minutes),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Convert.FromBase64String(input.Customer.Secret)),
                input.Customer.SecurityAlgorithm),
                IssuedAt = DateTime.UtcNow
            }));
        }
    }
}
