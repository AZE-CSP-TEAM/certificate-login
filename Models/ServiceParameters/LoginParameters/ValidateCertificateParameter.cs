using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

namespace Models.ServiceParameters.LoginParameters
{
    public class ValidateCertificateInput : ServiceInput
    {
        public X509Certificate2 LoginCertificate { get; set; }
    }

    public class ValidateCertificateOutput : ServiceOutput
    {
        public List<Claim> CertificateClaims { get; set; }
    }
}
