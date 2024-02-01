using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;


namespace CertAuth.Installers
{
    public interface IInstaller
    {
        void InstallServices(IServiceCollection services, IConfiguration configuration);
    }
}
