using DataAccess.Database;
using Models.Dtos.RepositoriesDtos.CustomerRepositoryDtos;
using System.Threading.Tasks;

namespace DataAccess.Repositories.CustomerRepository
{
    public class CustomerRepository : RepositoryBase, ICustomerRepository
    {
        public CustomerRepository(DapperDbContext dbContext) : base(dbContext) { }

        public async Task<GetCustomerByUrlDto> GetCustomerByUrl(string url)
            => await QueryFirstOrLastAsync<GetCustomerByUrlDto>(nameof(GetCustomerByUrl), url, nameof(url));
    }
}
