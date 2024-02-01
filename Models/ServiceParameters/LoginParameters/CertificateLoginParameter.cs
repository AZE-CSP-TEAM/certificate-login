using System.Collections.Generic;
using System.Security.Claims;

namespace Models.ServiceParameters.LoginParameters
{
    public class CertificateLoginInput: ServiceInput
    {
        public string Origin { get; set; }
        public List<Claim> Claims { get; set; }
    }
}
