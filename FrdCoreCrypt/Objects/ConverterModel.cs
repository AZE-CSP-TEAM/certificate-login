using System;
using System.Collections.Generic;
using System.Security.Claims;

namespace FrdCoreCrypt.Objects
{
    public class CertificateClaimConverterModel
    {
        public List<Claim> Claims { get; set; }
        public CertificateStatusObject CertificateStatus { get; set; }
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
        public string Aki { get; set; }
        public bool ChainValidationStatus { get; set; }
    }
}
