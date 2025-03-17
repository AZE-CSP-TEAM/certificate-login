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
        private readonly RSA _privateKey;
        private readonly string _securityAlgorithm;

        public TokenHelper(RsaKeyProvider rsaKeyProvider)
        {
            _privateKey = rsaKeyProvider.GetPrivateKey();
            _securityAlgorithm = SecurityAlgorithms.RsaSha256;
        }

        public string GenerateToken(TokenInput input)
        {
            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
            var signingCredentials = new SigningCredentials(new RsaSecurityKey(_privateKey), _securityAlgorithm);

            return tokenHandler.WriteToken(tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(input.Claims),
                Issuer = input.Issuer,
                Expires = DateTime.UtcNow.AddMinutes(5),
                SigningCredentials = signingCredentials,
                IssuedAt = DateTime.UtcNow
            }));
        }
    }
}
