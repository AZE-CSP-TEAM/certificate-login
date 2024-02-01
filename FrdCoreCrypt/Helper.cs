extern alias BC;

using System;
using System.Security.Cryptography.X509Certificates;
using BC::Org.BouncyCastle.Asn1;
using BC::Org.BouncyCastle.Asn1.X509;
using FrdCoreCrypt.Objects.Static;

namespace FrdCoreCrypt
{
    public static class Helper
    {
        public static string GetAuthorityKeyIdentifier(this X509Certificate2 certificate)
        {
            Asn1OctetString ext = certificate.ConvertToBCX509Certificate().GetExtensionValue(
                new DerObjectIdentifier(CertificateOIDS.AuthorityKeyIdentifier));

            if (ext == null)
            {
                return null;
            }

            return BitConverter.ToString(AuthorityKeyIdentifier.GetInstance(ext.GetOctets()).GetKeyIdentifier()).Replace("-", "");
        }
    }
}
