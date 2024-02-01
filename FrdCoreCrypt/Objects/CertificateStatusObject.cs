using FrdCoreCrypt.Enums;
using System;

namespace FrdCoreCrypt.Objects
{
    public class CertificateStatusObject
    {
        public CertificateStatusEnum  Status { get; private set; }
        public DateTime ProducedUTC { get; private set; }
        public string SignatureAlgName { get; private set; }

        public CertificateStatusObject(CertificateStatusEnum state) => Status = state;
        public CertificateStatusObject(DateTime produced, string algname, CertificateStatusEnum status) => SetStatus(produced, algname, status);

        public void SetStatus(DateTime produced, string algname, CertificateStatusEnum state )
        {
            Status = state;
            ProducedUTC = produced;
            SignatureAlgName = algname;
        }
    }
}
