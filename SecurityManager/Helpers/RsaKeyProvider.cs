using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SecurityManager.Helpers
{
    public class RsaKeyProvider
    {
        private readonly string _privateKeyPath;
        private readonly string _publicKeyPath;
        private readonly RSA _privateKey;
        private readonly RSA _publicKey;

        public RsaKeyProvider(string privateKeyPath = "private.pem", string publicKeyPath = "public.pem")
        {
            _privateKeyPath = privateKeyPath;
            _publicKeyPath = publicKeyPath;
            _privateKey = RSA.Create();
            _publicKey = RSA.Create();

            LoadOrGenerateKeys();
        }

        private void LoadOrGenerateKeys()
        {
            if (File.Exists(_privateKeyPath) && File.Exists(_publicKeyPath))
            {
                // Gettimg keys from files
                _privateKey.ImportRSAPrivateKey(File.ReadAllBytes(_privateKeyPath), out _);
                _publicKey.ImportSubjectPublicKeyInfo(File.ReadAllBytes(_publicKeyPath), out _);
            }
            else
            {
                // Generating new keys
                _privateKey.KeySize = 2048; 
                _publicKey.KeySize = 2048;

                // Saving the keys to files
                File.WriteAllBytes(_privateKeyPath, _privateKey.ExportRSAPrivateKey());
                File.WriteAllBytes(_publicKeyPath, _privateKey.ExportSubjectPublicKeyInfo());

                // Saving in PEM format (readable files)
                File.WriteAllText("private_pem.pem", ConvertToPem(_privateKey.ExportRSAPrivateKey(), "PRIVATE KEY"));
                File.WriteAllText("public_pem.pem", ConvertToPem(_privateKey.ExportSubjectPublicKeyInfo(), "PUBLIC KEY"));
            }
        }

        public RSA GetPrivateKey() => _privateKey;
        public RSA GetPublicKey() => _publicKey;

        private static string ConvertToPem(byte[] keyData, string keyType)
        {
            string base64 = Convert.ToBase64String(keyData);
            StringBuilder sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN {keyType}-----");
            for (int i = 0; i < base64.Length; i += 64)
            {
                sb.AppendLine(base64.Substring(i, Math.Min(64, base64.Length - i)));
            }
            sb.AppendLine($"-----END {keyType}-----");
            return sb.ToString();
        }
    }
}