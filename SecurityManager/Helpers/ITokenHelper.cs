using SecurityManager.Models;

namespace SecurityManager.Helpers
{
    public interface ITokenHelper
    {
        string GenerateSecureSecret();
        string GenerateToken(TokenInput input);
    }
}