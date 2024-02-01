using System;
using System.Linq;
using System.Net.Security;

namespace CertAuth.Helpers
{
    public static class ChiperHelper
    {

        public static CipherSuitesPolicy GetTls12CipherSuites()
        {
            return new CipherSuitesPolicy(
                            new[]
                            {
                                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
                                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
                                TlsCipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256,
                                TlsCipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384,
                                TlsCipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256,
                                TlsCipherSuite.TLS_PSK_WITH_AES_256_GCM_SHA384,
                                TlsCipherSuite.TLS_DHE_PSK_WITH_AES_128_GCM_SHA256,
                                TlsCipherSuite.TLS_DHE_PSK_WITH_AES_256_GCM_SHA384,
                                TlsCipherSuite.TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
                                TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                                TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                                TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                                TlsCipherSuite.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
                                TlsCipherSuite.TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256,
                                TlsCipherSuite.TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384,
                                TlsCipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256,
                                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM,
                                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM,
                                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CCM_8,
                                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CCM_8,
                                TlsCipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                                TlsCipherSuite.TLS_PSK_WITH_AES_128_CCM,
                                TlsCipherSuite.TLS_PSK_WITH_AES_256_CCM,
                                TlsCipherSuite.TLS_DHE_PSK_WITH_AES_128_CCM,
                                TlsCipherSuite.TLS_DHE_PSK_WITH_AES_256_CCM,
                                TlsCipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
                                TlsCipherSuite.TLS_PSK_WITH_AES_256_CCM_8,
                                TlsCipherSuite.TLS_PSK_DHE_WITH_AES_128_CCM_8,
                                TlsCipherSuite.TLS_PSK_DHE_WITH_AES_256_CCM_8,
                                TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
                                TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
                                TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
                                TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8,
                                TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256



                            });
        }


        public static CipherSuitesPolicy GetDefaultCipherPOlicy()
        {
            return new CipherSuitesPolicy(
                new TlsCipherSuite[]
                {
                    TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

                    TlsCipherSuite.TLS_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,


                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                    TlsCipherSuite.TLS_AES_128_CCM_SHA256,
                    TlsCipherSuite.TLS_AES_128_CCM_8_SHA256,

                    TlsCipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256,
                    TlsCipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384,
                    TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
                    TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA
                });
        }


        public static CipherSuitesPolicy GetAllCipherSuitesPolicy()
        {
            return new CipherSuitesPolicy(Enum.GetValues<TlsCipherSuite>().ToArray());
        }

    }
}
