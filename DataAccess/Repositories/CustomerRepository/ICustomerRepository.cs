using Models.Dtos.RepositoriesDtos.CustomerRepositoryDtos;
using System.Threading.Tasks;

namespace DataAccess.Repositories.CustomerRepository
{
    public interface ICustomerRepository
    {
        Task<GetCustomerByUrlDto> GetCustomerByUrl(string url);
    }
}
