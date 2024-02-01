using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Services.Services.UserServices;

namespace Web.Installers
{
    public class ServiceInstaller : IInstaller
	{
		public void InstallServices(IServiceCollection services, IConfiguration configuration)
		{
			services.AddSingleton(configuration);
			services.AddTransient<IUserService, UserService>();
		}
	}
}
