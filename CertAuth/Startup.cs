using System;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using CertAuth.Installers;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Models;
using Models.ServiceParameters.LoginParameters;
using SecurityManager.Helpers;
using Services.Services.CertificateValidationServices;

namespace CertAuth
{
    public class Startup
    {

        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration) => Configuration = configuration;

        public void ConfigureServices( IServiceCollection services)
        {
            //   app.UseHttpsRedirection();

            // Adding the RsaKeyProvider as a Singleton (so that one key is used everywhere)
            services.AddSingleton<RsaKeyProvider>();

            // Adding TokenHelper as a Transient (a new object each time)
            services.AddTransient<ITokenHelper, TokenHelper>();
            services.AddHsts(options =>
            {
                options.Preload = true;
                options.IncludeSubDomains = true;
                options.MaxAge = TimeSpan.FromDays(60);
                //options.ExcludedHosts.Add("example.com");
                //options.ExcludedHosts.Add("www.example.com");
            });

            services.InstallServicesAssembly(Configuration);
            
            services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
            .AddCertificate(options =>
            {
                options.AllowedCertificateTypes = CertificateTypes.Chained;
                options.RevocationFlag = System.Security.Cryptography.X509Certificates.X509RevocationFlag.EntireChain;
                options.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
                options.Events = new CertificateAuthenticationEvents
                {
                    
                    OnCertificateValidated = async (context) =>
                    {
                        if (context.ClientCertificate == null)
                        {
                            context.Fail("Certificate is null");
                            return;
                        }
                        Console.WriteLine("Validation Start");
                        ContainerResult<ValidateCertificateOutput> data = await context.HttpContext.RequestServices
                        .GetService<ICertificateValidationService>().ValidateCertificate(new ValidateCertificateInput
                        {
                            LoginCertificate = context.ClientCertificate
                        });

                        if (!data.IsSuccess)
                        {
                            context.Fail(data.ErrorList[0].ErrorMessage);
                            return;
                        }
                        context.Principal = new ClaimsPrincipal(new ClaimsIdentity(data.Output.CertificateClaims, context.Scheme.Name));

                        context.Success();
                        
                    } 

                    //OnAuthenticationFailed = async context =>
                    //{
                    //    //context.Fail("INvalid Cert");
                    //} ,
                    //OnChallenge = async context =>
                    //{

                    //    var rs = context.Request; 
                    //}
                    
                };
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();
            app.UseRouting();
            app.UseCertificateForwarding();
            app.UseAuthentication();
            app.UseCors(x => x.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
            app.UseAuthorization();
            app.UseEndpoints(endpoints => endpoints.MapControllers());
        }
    }
}
