using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using DataAccess.UnitofWork;
using DataAccess.Database;
using Microsoft.Data.SqlClient;

namespace CertAuth.Installers
{
    public class DbInstaller : IInstaller
	{
		public void InstallServices(IServiceCollection services, IConfiguration configuration)
		{
            services.AddTransient<IUnitOfWork, UnitOfWork>();
			services.AddTransient<DapperDbContext>();
			services.AddTransient<SqlConnection>();
		}
	}
}
