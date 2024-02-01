extern alias BC;

using BC::Org.BouncyCastle.Asn1;
using BC::Org.BouncyCastle.X509;
using FrdCoreCrypt.Objects;
using FrdCoreCrypt.Objects.Static;
using System;
using System.Collections;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using X509Certificate = BC::Org.BouncyCastle.X509.X509Certificate;


namespace FrdCoreCrypt
{
    public static class CertManager
    {
        public static CertSubjectDetails GetUniqueName(X509Certificate2 certificate)
        {
            X509Certificate cert = certificate.ConvertToBCX509Certificate();
            IList list = cert.SubjectDN.GetOidList();
            IList values = cert.SubjectDN.GetValueList();

            if (list.Count != values.Count)
            {
                return null;
            }

            int indexofcmname = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.CommonName_OID));
            int indexofOrg = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.Organisation_OID));
            int indexoforgunit = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.OrganizationalUnit_OID));
            int indexoftitleOid = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.Title_OID));
            int indexofgivenname = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.GivenName_OID));
            int indexofsurname = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.Surname_OID));
            int indexofemail = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.Email_OID));
            int indexofuid = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.UserIdentifier_OID));
            int indexofloyality = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.Loyality_OID));
            int indexofinitials = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.Initials_OID));
            int indexofpostalcode = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.PostalCode_OID));
            int indexofstate = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.StateProvince_OID));
            int indexofcountry = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.CountryName_OID));
            int indexofserail = list.IndexOf(new DerObjectIdentifier(CertificateOIDS.SubjectOIds.SerialNUmber_OID));

            return new CertSubjectDetails
            {
                CommonName = (indexofcmname != -1) ? (string)values[indexofcmname] : null,
                GivenName = (indexofgivenname != -1) ? (string)values[indexofgivenname] : null,
                SerialNumber = (indexofserail != -1) ? (string)values[indexofserail] : null,
                Title = (indexoftitleOid != -1) ? (string)values[indexoftitleOid] : null,
                Surname = (indexofsurname != -1) ? (string)values[indexofsurname] : null,
                Organization = (indexofOrg != -1) ? (string)values[indexofOrg] : null,
                OrganizationUnit = (indexoforgunit != -1) ? (string)values[indexoforgunit] : null,
                Email = (indexofemail != -1) ? (string)values[indexofemail] : null,
                UserId = (indexofuid != -1) ? (string)values[indexofuid] : null,
                Loyalty = (indexofloyality != -1) ? (string)values[indexofloyality] : null,
                Initial = (indexofinitials != -1) ? (string)values[indexofinitials] : null,
                PostalCode = (indexofpostalcode != -1) ? (string)values[indexofpostalcode] : null,
                StateProvince = (indexofstate != -1) ? (string)values[indexofstate] : null,
                Country = (indexofcountry != -1) ? (string)values[indexofcountry] : null,
            };
        }

        public static X509Certificate ConvertToBCX509Certificate(this X509Certificate2 cert) =>
            new X509CertificateParser().ReadCertificate(cert.Export(X509ContentType.Cert));

        public static void ParseExtension(X509Certificate2 cert)
        {
            CertSubjectDetails certSubjectDetails = GetUniqueName(cert);
            FrdOcspClient ocspclient = new FrdOcspClient();

            CertificateStatusObject certificateStatusObject = ocspclient.ValidateOCSPx509_2(cert);

            // string empi = cert.GetExtentionValue(CertificateOIDS.SubjectAlternativeName); 
            foreach (X509Extension extension in cert.Extensions)
            {
                AsnEncodedData asndata = new AsnEncodedData(extension.Oid, extension.RawData);
                Console.WriteLine("Extension type: {0}", extension.Oid.FriendlyName);
                Console.WriteLine("Oid value: {0}", asndata.Oid.Value);
                Console.WriteLine("Raw data length: {0} {1}", asndata.RawData.Length, Environment.NewLine);
                Console.WriteLine(asndata.Format(true));
            }

            string subject = cert.GetNameInfo(X509NameType.DnsName, false);
            string commonName = cert.GetNameInfo(X509NameType.SimpleName, false);
        }
    }
}
