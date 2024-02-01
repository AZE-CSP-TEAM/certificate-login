using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Reflection;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using log4net;
using log4net.Config;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace CertAuth
{
    public class Program
    {
        public static IConfiguration Configuration { get; private set; }

        public static void Main(string[] args)
        {
            //   CreateHostBuilder(args).Build().Run();
            CreatedefaultKestrelMode(args).Build().Run();
            //   CreateWebHostBuilder(args).Build().Run();

        } 


        // public static void Main(string[] args) => CreateWebHostBuilder(args).Build().Run();

        public static void BuildConfiguration()
        {
            var builder = new ConfigurationBuilder()
           //.SetBasePath(env.ContentRootPath)
           .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
           //.AddJsonFile($"appsettings.{}.json", optional: true)
           .AddEnvironmentVariables();

            Configuration = builder.Build();
        }

        public static IHostBuilder CreateHostBuilder(string[] args)
        {
            BuildConfiguration();

            XmlConfigurator.Configure(LogManager.GetRepository(Assembly.GetEntryAssembly()), new FileInfo("log4net.config"));

            //X509Certificate2 certificate = GetServiceCertificate(Configuration.GetSection("AppSetting")["SSlCertname"], Configuration.GetSection("AppSetting")["SSLCertPassw"]);

            IConfigurationSection sha1RootConfigurationSection = Configuration.GetSection("Certificates:SHA1Root");
            X509Certificate2 certificate = new(Convert.FromBase64String(sha1RootConfigurationSection["Certificate"]), "");
            Console.WriteLine($"{certificate.Subject}");
            IHostBuilder whb = Host.CreateDefaultBuilder(args).ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
                webBuilder.ConfigureKestrel(o =>
                {
                    o.ConfigureHttpsDefaults(o =>
                    {
                        o.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                        o.CheckCertificateRevocation = false;
                        o.ClientCertificateValidation = (certificate2, chain, arg3) =>
                        {
                            return true;
                        };
                       // o.ServerCertificateSelector
                        //o.OnAuthenticate
                    });


                });

                //  var port = Configuration.GetSection("AppSetting")["PortNumber"]; 
                var port = Configuration.GetSection("AppSetting")["PortNumber"];
                webBuilder.UseKestrel(options =>
                {

                    options.Listen(new IPEndPoint(IPAddress.Any, Convert.ToInt32(port)), listenOptions =>
                    {
                        listenOptions.UseConnectionLogging();
                        HttpsConnectionAdapterOptions httpsConnectionAdapterOptions = new()
                        {
                            ClientCertificateMode = ClientCertificateMode.RequireCertificate,
                            SslProtocols = System.Security.Authentication.SslProtocols.Tls11 | System.Security.Authentication.SslProtocols.Tls12,
                            ServerCertificate = certificate,
                            //ServerCertificateSelector= (connectionContext, name) =>
                            //{
                            //    return null ;
                            //}
                        };


                       
                      
                        
                        // listenOptions.UseHttps(httpsConnectionAdapterOptions);
                        listenOptions.UseHttps((stream, clientHelloInfo, state, cancellationToken) =>
                        {

                            Console.WriteLine(clientHelloInfo.SslProtocols);
                            Console.WriteLine(clientHelloInfo.ServerName);
                            Console.WriteLine(state);

                            return new ValueTask<SslServerAuthenticationOptions>(
                                new SslServerAuthenticationOptions
                                {
                                    ClientCertificateRequired = true,
                                    ServerCertificate = certificate,
                                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,

                                    EnabledSslProtocols = SslProtocols.Tls11 | SslProtocols.Tls12,
                                    RemoteCertificateValidationCallback = (sender, x509Certificate, chain, errors) =>
                                    {
                                        if (x509Certificate != null)
                                        {
                                            Console.WriteLine(x509Certificate.Subject);
                                        }
                                       
                                        return true;
                                    },
                                   // CipherSuitesPolicy = tls12suites
                                });
                        }, state: null!);
                        listenOptions.Protocols = HttpProtocols.Http1AndHttp2;

                        Console.WriteLine($"{listenOptions.IPEndPoint} - {listenOptions.Protocols} - {listenOptions.SocketPath}");
                    });
                });
            });

            return whb;
        }

        public static IHostBuilder CreatedefaultKestrelMode(string[] args)
        {
            AppContext.SetSwitch("Microsoft.AspNetCore.Server.Kestrel.EnableWindows81Http2", true);
            BuildConfiguration();

            XmlConfigurator.Configure(LogManager.GetRepository(Assembly.GetEntryAssembly()), new FileInfo("log4net.config"));

            X509Certificate2 certificate = GetServiceCertificate(Configuration.GetSection("AppSetting")["SSlCertname"], Configuration.GetSection("AppSetting")["SSLCertPassw"]);
            IHostBuilder whb = Host.CreateDefaultBuilder(args).ConfigureWebHostDefaults(webBuilder =>
            {
                webBuilder.UseStartup<Startup>();
                webBuilder.ConfigureKestrel(o =>
                {
                    o.ConfigureHttpsDefaults(o => o.ClientCertificateMode = ClientCertificateMode.RequireCertificate);
                });

                webBuilder.UseKestrel(options =>
                {
                    options.Listen(new IPEndPoint(IPAddress.Any, Convert.ToInt32(Configuration.GetSection("AppSetting")["PortNumber"])), listenOptions =>
                    {
                        var httpsConnectionAdapterOptions = new HttpsConnectionAdapterOptions()
                        {
                            ClientCertificateMode = ClientCertificateMode.RequireCertificate,
                            SslProtocols = System.Security.Authentication.SslProtocols.Tls12,
                            ServerCertificate = certificate
                            //,
                            //ServerCertificateSelector= (connectionContext, name) =>
                            //{
                            //    return null ;
                            //}
                        };
                        listenOptions.UseHttps(httpsConnectionAdapterOptions);
                        listenOptions.Protocols = HttpProtocols.Http1;
                    });
                });
            });

            return whb;

        }
        public static IWebHostBuilder CreateWebHostBuilder(string[] args)
        {
            BuildConfiguration();

            XmlConfigurator.Configure(LogManager.GetRepository(Assembly.GetEntryAssembly()), new FileInfo("log4net.config"));

            //X509Certificate2 certificate = GetServiceCertificate(Configuration.GetSection("AppSetting")["SSlCertname"], Configuration.GetSection("AppSetting")["SSLCertPassw"]);

            IConfigurationSection sha1RootConfigurationSection = Configuration.GetSection("Certificates:SHA1Root");
            X509Certificate2 certificate = new(Convert.FromBase64String(sha1RootConfigurationSection["Certificate"]), "");

            IWebHostBuilder webBuilder = WebHost.CreateDefaultBuilder(args);

            webBuilder.UseStartup<Startup>();
            webBuilder.ConfigureKestrel(o =>
            {
                o.ConfigureHttpsDefaults(o => o.ClientCertificateMode = ClientCertificateMode.RequireCertificate);
            });
            var port = Configuration.GetSection("AppSetting")["PortNumber"];
            webBuilder.UseKestrel(options =>
            {
                options.Listen(new IPEndPoint(IPAddress.Loopback, Convert.ToInt32(port)), listenOptions =>
                {
                    HttpsConnectionAdapterOptions httpsConnectionAdapterOptions = new()
                    {
                        ClientCertificateMode = ClientCertificateMode.AllowCertificate,
                        SslProtocols = System.Security.Authentication.SslProtocols.Tls12,
                        ServerCertificate = certificate
                    };
                    listenOptions.UseHttps(httpsConnectionAdapterOptions);
                    listenOptions.Protocols = HttpProtocols.Http1;
                });
            });

            return webBuilder;
        }

        private static X509Certificate2 GetServiceCertificate(string subjectName, string password)
        {
            return new X509Certificate2(File.ReadAllBytes(subjectName), password);

            //using (var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            //{
            //    certStore.Open(OpenFlags.ReadOnly);
            //    var certCollection = certStore.Certificates.Find(
            //                               X509FindType.FindBySubjectDistinguishedName, subjectName, false);
            //    // Get the first certificate
            //    X509Certificate2 certificate = null;
            //    if (certCollection.Count > 0)
            //    {
            //        certificate = certCollection[0];
            //    }
            //    return certificate;
            //}
        }
    }
}
