using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Services.Services.UserServices;
using Services.Services.CertificateValidationServices;
using SecurityManager.Helpers;
using FrdCoreCrypt.Converters;

namespace CertAuth.Installers
{
    public class ServiceInstaller : IInstaller
	{
		public void InstallServices(IServiceCollection services, IConfiguration configuration)
		{
			services.AddSingleton(configuration);
            services.AddTransient<IUserService, UserService>();
            services.AddTransient<ICertificateValidationService, CertificateValidationService>();
            services.AddTransient<ITokenHelper, TokenHelper>();
            services.AddTransient<ICertificateClaimConverter, CertificateClaimConverter>();
        }
	}
}
