using DataAccess.UnitofWork;

namespace Services.Services.UserServices
{
    public class UserService : AbstractService, IUserService
    {
        public UserService(IUnitOfWork UoW) : base(UoW) { }

        //public async Task<ContainerResult<GetOrganizationByIdOutput>> GetOrganizationByIdAsync(GetOrganizationByIdInput input)
        //    => await ExecuteAsync(ConnectionTypes.CONNECTION, async () =>
        //    {
        //        ContainerResult<GetOrganizationByIdOutput> Result = new ContainerResult<GetOrganizationByIdOutput>();

        //        if (await _uow.OrganizationRepository().GetOrganizationByIdCount(input.OrganizationId) == 0)
        //        {
        //            Result.ErrorList.Add(new Error
        //            {
        //                ErrorCode = ErrorCodes.ORGANIZATION_DOES_NOT_EXIST,
        //                ErrorMessage = Resource.ORGANIZATION_DOES_NOT_EXIST,
        //                StatusCode = ErrorHttpStatus.NOT_FOUND
        //            });

        //            return Result;
        //        }

        //        Result.Output = new GetOrganizationByIdOutput
        //        {
        //            Organization = await _uow.OrganizationRepository().GetOrganizationById(input.OrganizationId)
        //        };

        //        return Result;
        //    });

    }
}
