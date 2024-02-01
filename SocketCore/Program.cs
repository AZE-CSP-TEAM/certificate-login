using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Security.Authentication;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.Configuration;

class Program
{

    static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);


        builder.Services
            .AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
            .AddCertificate(options =>
            {
                options.RevocationMode = X509RevocationMode.NoCheck;
                options.AllowedCertificateTypes = CertificateTypes.All;
                options.AllowedCertificateTypes = CertificateTypes.Chained; 
               // options
                options.Events = new CertificateAuthenticationEvents
                {
                    OnCertificateValidated = context =>
                    {

                        var cert = context.ClientCertificate;
                        Console.WriteLine(cert);
                        // Perform additional validation if needed
                        // For example, check the client's certificate against a list of valid certificates
                        //if (!IsValidCertificate(context.ClientCertificate))
                        //{
                        //    context.Fail("Invalid certificate.");
                        //}
                        context.Success();
                        return Task.CompletedTask;
                    } , 
                    OnAuthenticationFailed =async context =>
                    {
                        context.Fail("invalid cert");
                        
                    } ,
                    OnChallenge = async context =>
                    {
                       var req =  context.Request; 
                    }
                };

            });

        X509Certificate2 certificate = new("e-imza.pfx", "");

        builder.Services.Configure<KestrelServerOptions>(options =>
        {
            options.ConfigureHttpsDefaults(options =>
            {
                options.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                options.SslProtocols = SslProtocols.Tls12; 
                options.ServerCertificate = certificate;
                
            });

            options.Listen(IPAddress.Loopback, 443, listenOptions =>
            {
              //  listenOptions.UseHttps()

            });


        });
        var app = builder.Build();
        app.UseCertificateForwarding();
        app.UseHttpsRedirection(); // Ensure the server uses HTTPS

        app.UseAuthentication(); // Enable authentication


        app.MapGet("/", () => "Hello World!");

        app.Run();

    }



    static async Task OldCall(string[] args)
    {

    }
}