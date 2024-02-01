extern alias BC;
using FrdCoreCrypt.Objects;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Claims;
using System.Linq;
using FrdCoreCrypt.Enums;

namespace FrdCoreCrypt.Converters
{
    public class CertificateClaimConverter : ICertificateClaimConverter
    {

        public CertificateClaimConverterModel GetClaimsFromCertificate(X509Certificate2 certificate)
        {
            CertSubjectDetails uniquename = CertManager.GetUniqueName(certificate);

            List<Claim> claims = uniquename.Claims.Values.ToList();

            claims.Add(new Claim(ClaimTypes.NameIdentifier, uniquename.Claims[CertificateClaims.SubjectSerialNumber].Value, ClaimValueTypes.String));

            FrdOcspClient ocspClient = new FrdOcspClient();

            CertificateStatusObject ocspresult = ocspClient.ValidateOCSPx509_2(certificate);

            Claim ocsptimeClaim = new Claim(CertificateClaims.CertificateOCSPResultTime, ocspresult.ProducedUTC.ToString(), ClaimValueTypes.DateTime);
            Claim ocspResultClaim = new Claim(CertificateClaims.CertificateOCSPStatus, ocspresult.Status.ToString(), ClaimValueTypes.DateTime);

            Claim certVFR = new Claim(CertificateClaims.CertificateValidFrom, certificate.NotBefore.ToString(), ClaimValueTypes.DateTime);

            Claim certVTO = new Claim(CertificateClaims.CertificateValidTo, certificate.NotAfter.ToString(), ClaimValueTypes.DateTime);

            bool chainstatus = ocspClient.ValidateCertificateChain(certificate);
            Claim certChainStatus = new Claim(CertificateClaims.CertificateChainValidation, chainstatus.ToString(), ClaimValueTypes.Boolean);

            string aki = certificate.GetAuthorityKeyIdentifier();

            claims.AddRange(new Claim[] { ocspResultClaim, ocsptimeClaim, certChainStatus, certVFR, certVTO });

            if (aki != null)
            {
                claims.Add(new Claim(CertificateClaims.CertificateAuthorityKeyIdentifier, aki));
            }

            return new CertificateClaimConverterModel
            {
                Claims = claims,
                Aki = aki,
                CertificateStatus = ocspresult,
                ChainValidationStatus = chainstatus,
                ValidFrom = certificate.NotBefore,
                ValidTo = certificate.NotAfter
            };
        }
    }
}
