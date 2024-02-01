using FrdCoreCrypt.Objects;
using System.Security.Cryptography.X509Certificates;

namespace FrdCoreCrypt.Converters
{
    public interface ICertificateClaimConverter
    {
        CertificateClaimConverterModel GetClaimsFromCertificate(X509Certificate2 certificate);
    }
}