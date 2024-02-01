using Common;
using Common.Enums.CommonEnums;
using Common.Enums.DatabaseEnums;
using Common.Enums.ErrorEnums;
using Common.Resources;
using DataAccess.UnitofWork;
using FrdCoreCrypt.Converters;
using FrdCoreCrypt.Enums;
using FrdCoreCrypt.Objects;
using Microsoft.Extensions.Configuration;
using Models;
using Models.Dtos.RepositoriesDtos.CustomerRepositoryDtos;
using Models.ServiceParameters.LoginParameters;
using SecurityManager.Helpers;
using SecurityManager.Models;
using System;
using System.Threading.Tasks;

namespace Services.Services.CertificateValidationServices
{
    public class CertificateValidationService : AbstractService, ICertificateValidationService
    {
        private readonly IConfiguration _configuration;
        private readonly ITokenHelper _tokenHelper;
        private readonly ICertificateClaimConverter _certificateClaimConverter;

        public CertificateValidationService(IUnitOfWork UoW, IConfiguration configuration, ITokenHelper tokenHelper,
            ICertificateClaimConverter certificateClaimConverter) : base(UoW)
        {
            _configuration = configuration;
            _tokenHelper = tokenHelper;
            _certificateClaimConverter = certificateClaimConverter;
        }

        public async Task<ContainerResult<string>> Login(CertificateLoginInput input)
            => await ExecuteAsync(ConnectionTypes.CONNECTION, async () =>
        {
            ContainerResult<string> result = new ContainerResult<string>();

            input.Origin = input.Origin?.Trim()?.ToLower();

            if (string.IsNullOrEmpty(input.Origin))
            {
                result.ErrorList.Add(new Error
                {
                    ErrorCode = ErrorCodes.ORIGIN_IS_EMPTY,
                    ErrorMessage = Resource.ORIGIN_IS_EMPTY,
                    StatusCode = ErrorHttpStatus.FORBIDDEN
                });

                return result;
            }

            if (!(input.Claims?.Count > 0))
            {
                result.ErrorList.Add(new Error
                {
                    ErrorCode = ErrorCodes.CLAIMS_ARE_EMPTY,
                    ErrorMessage = Resource.CLAIMS_ARE_EMPTY,
                    StatusCode = ErrorHttpStatus.FORBIDDEN
                });

                return result;
            }

            GetCustomerByUrlDto customerByUrl = await _uow.CustomerRepository().GetCustomerByUrl(input.Origin);

            if (customerByUrl == null)
            {
                result.ErrorList.Add(new Error
                {
                    ErrorCode = ErrorCodes.CUSTOMER_DOES_NOT_EXIST,
                    ErrorMessage = Resource.CUSTOMER_DOES_NOT_EXIST,
                    StatusCode = ErrorHttpStatus.NOTFOUND
                });

                return result;
            }

            if (customerByUrl.OrganizationStatusId == (byte)OrganizationStatuses.BLOCKED)
            {
                result.ErrorList.Add(new Error
                {
                    ErrorCode = ErrorCodes.ORGANIZATION_IS_BLOCKED,
                    ErrorMessage = Resource.ORGANIZATION_IS_BLOCKED,
                    StatusCode = ErrorHttpStatus.NOTFOUND
                });

                return result;
            }

            if (customerByUrl.SubOrganizationStatusId == (byte)SubOrganizationStatuses.BLOCKED)
            {
                result.ErrorList.Add(new Error
                {
                    ErrorCode = ErrorCodes.SUB_ORGANIZATION_IS_BLOCKED,
                    ErrorMessage = Resource.SUB_ORGANIZATION_IS_BLOCKED,
                    StatusCode = ErrorHttpStatus.FORBIDDEN
                });

                return result;
            }

            if (customerByUrl.CustomerStatusId == (byte)CustomerStatuses.BLOCKED)
            {
                result.ErrorList.Add(new Error
                {
                    ErrorCode = ErrorCodes.CUSTOMER_IS_BLOCKED,
                    ErrorMessage = Resource.CUSTOMER_IS_BLOCKED,
                    StatusCode = ErrorHttpStatus.FORBIDDEN
                });

                return result;
            }

            result.Output = _tokenHelper.GenerateToken(new TokenInput
            {
                Issuer = _configuration.GetSection("AppSetting")["Issuer"],
                Claims = input.Claims,
                Customer = new Customer
                {
                    Audience = input.Origin,
                    Minutes = customerByUrl.Minutues,
                    Secret = customerByUrl.SecretKey,
                    SecurityAlgorithm = customerByUrl.Algorithm
                }
            });

            await Task.CompletedTask;
            return result;
        });

        public async Task<ContainerResult<ValidateCertificateOutput>> ValidateCertificate(ValidateCertificateInput input)
           => await ExecuteAsync(ConnectionTypes.NONE, async () =>
        {
            ContainerResult<ValidateCertificateOutput> result = new ContainerResult<ValidateCertificateOutput>();

            CertificateClaimConverterModel certificateClaimConverterModel = _certificateClaimConverter
            .GetClaimsFromCertificate(input.LoginCertificate);

            Console.WriteLine($"CertificateClaims : {certificateClaimConverterModel.ChainValidationStatus}");
            if (certificateClaimConverterModel.CertificateStatus.Status != CertificateStatusEnum.Good)
            {
                result.ErrorList.Add(new Error
                {
                    ErrorCode = ErrorCodes.CERTIFICATE_STATUS_IS_NOT_GOOD,
                    ErrorMessage = Resource.CERTIFICATE_STATUS_IS_NOT_GOOD,
                    StatusCode = ErrorHttpStatus.FORBIDDEN
                });

                return result;
            }

            if (!certificateClaimConverterModel.ChainValidationStatus)
            {
                result.ErrorList.Add(new Error
                {
                    ErrorCode = ErrorCodes.CHAIN_VALIDATION_STATUS_IS_NOT_GOOD,
                    ErrorMessage = Resource.CHAIN_VALIDATION_STATUS_IS_NOT_GOOD,
                    StatusCode = ErrorHttpStatus.FORBIDDEN
                });

                return result;
            }

            if (!input.LoginCertificate.Verify())
            {
                result.ErrorList.Add(new Error
                {
                    ErrorCode = ErrorCodes.LOGIN_CERTIFICATE_VERIFICATION_IS_NOT_GOOD,
                    ErrorMessage = Resource.LOGIN_CERTIFICATE_VERIFICATION_IS_NOT_GOOD,
                    StatusCode = ErrorHttpStatus.FORBIDDEN
                });

                return result;
            }

            result.Output = new ValidateCertificateOutput
            {
                CertificateClaims = certificateClaimConverterModel.Claims
            };

            await Task.CompletedTask;
            return result;
        });
    }
}
