using DataAccess.Database;

namespace DataAccess.Repositories.UserRepository
{
    public class UserRepository : RepositoryBase, IUserRepository
    {
        public UserRepository(DapperDbContext dbContext) : base(dbContext) { }

        //public async Task<GetOrganizationByParameterDto> GetOrganizationById(int organizationId)
        //    => await QueryFirstOrLastAsync<GetOrganizationByParameterDto>(nameof(GetOrganizationById), organizationId, nameof(organizationId));

        //public async Task<int> GetOrganizationByIdCount(int organizationId)
        //    => Convert.ToInt32(await ExecuteScalarAsync(nameof(GetOrganizationByIdCount), organizationId, nameof(organizationId)));

        //public async Task<IEnumerable<GetOrganizationsDto>> GetOrganizations(GetOrganizationsInputDto input)
        //    => await QueryAsync<GetOrganizationsDto>(nameof(GetOrganizations), input);

        //public async Task<int> InsertOrganization(InsertOrganizationInputDto input)
        //    => Convert.ToInt32(await ExecuteScalarAsync(nameof(InsertOrganization), input));

        //public async Task UpdateOrganization(UpdateOrganizationDtoInputDto input)
        //    => Convert.ToInt32(await ExecuteAsync(nameof(UpdateOrganization), input));
    }
}
