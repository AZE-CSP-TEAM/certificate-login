extern alias BC;

using BC::Org.BouncyCastle.Asn1;
using BC::Org.BouncyCastle.Asn1.Ocsp;
using BC::Org.BouncyCastle.Asn1.X509;
using BC::Org.BouncyCastle.Math;
using BC::Org.BouncyCastle.Ocsp;
using FrdCoreCrypt.Enums;
using FrdCoreCrypt.Objects;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using X509Certificate = BC::Org.BouncyCastle.X509.X509Certificate;
using X509Extension = BC::Org.BouncyCastle.Asn1.X509.X509Extension;

namespace FrdCoreCrypt
{
    public class FrdOcspClient
    {
        public static Asn1Object GetExtensionValue(X509Certificate cert, string oid)
        {
            if (cert == null)
            {
                return null;
            }

            byte[] bytes = cert.GetExtensionValue(new DerObjectIdentifier(oid)).GetOctets();

            if (bytes == null)
            {
                return null;
            }

            return new Asn1InputStream(bytes).ReadObject();
        }

        public List<string> GetAuthorityInformationAccessOcspUrlx5092(X509Certificate2 cert) =>
            GetAuthorityInformationAccessOcspUrl(cert.ConvertToBCX509Certificate());

        public List<string> GetAuthorityInformationAccessOcspUrl(X509Certificate cert)
        {
            List<string> ocspUrls = new List<string>();

            try
            {
                Asn1Object obj = GetExtensionValue(cert, X509Extensions.AuthorityInfoAccess.Id);

                if (obj == null)
                {
                    return null;
                }

                IEnumerator elements = ((Asn1Sequence)obj).GetEnumerator();

                while (elements.MoveNext())
                {
                    Asn1Sequence element = (Asn1Sequence)elements.Current;
                    DerObjectIdentifier oid = (DerObjectIdentifier)element[0];

                    if (oid.Id.Equals("1.3.6.1.5.5.7.48.1")) // Is Ocsp?
                    {
                        Asn1TaggedObject taggedObject = (Asn1TaggedObject)element[1];
                        GeneralName gn = (GeneralName)GeneralName.GetInstance(taggedObject);
                        ocspUrls.Add(((DerIA5String)DerIA5String.GetInstance(gn.Name)).GetString());
                    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("Error parsing AIA.", ex);
            }

            return ocspUrls;
        }

        public CertificateStatusObject ValidateOCSPx509_2(X509Certificate2 certificate) =>
            ValidateOCSPx509_2(certificate, GetIssuerCertificate(certificate));

        public CertificateStatusObject ValidateOCSPx509_2(X509Certificate2 cert, X509Certificate2 cacert)
            => ValidateOCSP(cert.ConvertToBCX509Certificate(), cacert.ConvertToBCX509Certificate());

        public CertificateStatusObject ValidateOCSP(X509Certificate cert, X509Certificate cacert)
        {
            List<string> urls = GetAuthorityInformationAccessOcspUrl(cert);

            if (urls.Count == 0)
            {
                throw new Exception("No OCSP url found in ee certificate.");
            }

            string url = urls[0];
            Console.WriteLine("Sending to :  '" + url + "'...");

            return VerifyResponse(PostRequest(url, CreateOCSPPackage(cert, cacert), "Content-Type", "application/ocsp-request"));
        }

        public byte[] ToByteArray(Stream stream)
        {
            using (MemoryStream ms = new MemoryStream())
            {
                byte[] buffer = new byte[4096 * 8];
                int read;

                while ((read = stream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    ms.Write(buffer, 0, read);
                }

                return ms.ToArray();
            }
        }

        public byte[] PostRequest(string url, byte[] data, string contentType, string accept)
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "POST";
            request.ContentType = contentType;
            request.ContentLength = data.Length;
            request.Accept = accept;
            using (Stream stream = request.GetRequestStream())
            {
                stream.Write(data, 0, data.Length);
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                using (Stream respStream = response.GetResponseStream())
                {
                    Console.WriteLine(string.Format("HttpStatusCode : {0}", response.StatusCode.ToString()));
                    return ToByteArray(respStream);
                }
            }
        }

        private CertificateStatusObject VerifyResponse(byte[] response)
        {
            OcspResp ocspResponse = new OcspResp(response);

            CertificateStatusEnum cStatusEnum = CertificateStatusEnum.Unknown;
            BasicOcspResp basicOcspResp = ocspResponse.GetResponseObject() as BasicOcspResp;

            switch (ocspResponse.Status)
            {
                case OcspRespStatus.Successful:

                    //ValidateResponse(or, issuerCert);
                    //Console.WriteLine(or.Responses.Length);
                    if (basicOcspResp.Responses.Length == 1)
                    {
                        SingleResp resp = basicOcspResp.Responses[0];
                        //ValidateCertificateId(issuerCert, eeCert, resp.GetCertID());
                        //ValidateThisUpdate(resp);
                        //ValidateNextUpdate(resp);

                        object certificateStatus = resp.GetCertStatus();

                        if (certificateStatus == null)
                        {
                            Console.WriteLine("Status is null ! ");
                        }

                        if (certificateStatus == null || certificateStatus == BC::Org.BouncyCastle.Ocsp.CertificateStatus.Good)
                        {
                            cStatusEnum = CertificateStatusEnum.Good;
                            Console.WriteLine("Status is GOOD ! ");
                        }
                        else if (certificateStatus is BC::Org.BouncyCastle.Ocsp.RevokedStatus)
                        {
                            cStatusEnum = CertificateStatusEnum.Revoked;
                            Console.WriteLine("Status is Revoked ! ");
                        }
                        else if (certificateStatus is BC::Org.BouncyCastle.Ocsp.UnknownStatus)
                        {
                            cStatusEnum = CertificateStatusEnum.Unknown;
                            Console.WriteLine("Status is Unknown ! ");
                        }
                    }
                    break;
                default:
                    throw new Exception("Unknow status '" + ocspResponse.Status + "'.");
            }
            CertificateStatusObject result;
           
            if (basicOcspResp != null)
            {
                result = new CertificateStatusObject(basicOcspResp.ProducedAt, basicOcspResp.SignatureAlgName, cStatusEnum);
            }
            else
            {
                result = new CertificateStatusObject(cStatusEnum);
            }

            //result = new CertificateStatusObject(or.ProducedAt )
            return result;
        }

        [Obsolete]
        private static byte[] CreateOCSPPackage(X509Certificate cert, X509Certificate cacert)
        {
            try
            {
                OcspReqGenerator gen = new OcspReqGenerator();
                gen.AddRequest(new CertificateID(CertificateID.HashSha1, cacert, cert.SerialNumber));
                gen.SetRequestExtensions(CreateExtension());
                return gen.Generate().GetEncoded();
            }
            catch (OcspException e)
            {
                Console.WriteLine(e.StackTrace);
            }
            catch (IOException e)
            {

                Console.WriteLine(e.StackTrace);
            }
            return null;
        }

        [Obsolete]
        private static X509Extensions CreateExtension() => new X509Extensions(new Hashtable
        {
            {
                OcspObjectIdentifiers.PkixOcspNonce,
                new X509Extension(false, new DerOctetString(BigInteger.ValueOf(DateTime.Now.Ticks).ToByteArray()))
            }
        });

        public bool ValidateCertificateChain(X509Certificate2 cert)
        {
            Console.WriteLine("Revokation Check");
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
           // chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
            chain.Build(cert);

            foreach (X509ChainElement item in chain.ChainElements)
            {
                Console.WriteLine($"Checking :  {item.Certificate.SubjectName.Name}");
                if (item.Certificate.Verify() == false)
                {
                    return false;
                }
            }

            return true;
        }

        public X509Certificate2 GetIssuerCertificate(X509Certificate2 cert)
        {
            if (cert.Subject == cert.Issuer)
            {
                return cert;
            }

            //Self Signed Certificate
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.Build(cert);
            X509Certificate2 issuer = null;
            if (chain.ChainElements.Count > 1)
            {
                issuer = chain.ChainElements[1].Certificate;
            }
            chain.Reset();
            return issuer;
        }
    }
}
