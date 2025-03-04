using Common;
using Common.Enums.CommonEnums;
using Common.Enums.ErrorEnums;
using Common.Resources;
using FrdCoreCrypt.Converters;
using FrdCoreCrypt.Enums;
using FrdCoreCrypt.Objects;
using Microsoft.Extensions.Configuration;
using Models;
using Models.ServiceParameters.LoginParameters;
using SecurityManager.Helpers;
using SecurityManager.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Services.Services.CertificateValidationServices
{
    public class CertificateValidationService : ICertificateValidationService
    {
        private readonly IConfiguration _configuration;
        private readonly ITokenHelper _tokenHelper;
        private readonly ICertificateClaimConverter _certificateClaimConverter;



        public CertificateValidationService(IConfiguration configuration, ITokenHelper tokenHelper,
            ICertificateClaimConverter certificateClaimConverter)
        {
            _configuration = configuration;
            _tokenHelper = tokenHelper;
            _certificateClaimConverter = certificateClaimConverter;
        }

        public async Task<ContainerResult<string>> Login(CertificateLoginInput input)
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

            result.Output = _tokenHelper.GenerateToken(new TokenInput
            {
                Issuer = _configuration.GetSection("AppSetting")["Issuer"],
                Claims = input.Claims,
            });

            return await Task.FromResult(result);
        }

        public async Task<ContainerResult<ValidateCertificateOutput>> ValidateCertificate(ValidateCertificateInput input)
        {
            ContainerResult<ValidateCertificateOutput> result = new ContainerResult<ValidateCertificateOutput>();

            // Проверка на null
            if (input?.LoginCertificate == null)
            {
                result.ErrorList.Add(new Error
                {
                    ErrorCode = ErrorCodes.INVALID_CERTIFICATE,
                    ErrorMessage = "The login certificate is missing or invalid.",
                    StatusCode = ErrorHttpStatus.FORBIDDEN
                });
                return result;
            }

            CertificateClaimConverterModel certificateClaimConverterModel = _certificateClaimConverter
                .GetClaimsFromCertificate(input.LoginCertificate);

            // Проверка на null для результата конвертации
            if (certificateClaimConverterModel == null || certificateClaimConverterModel.CertificateStatus == null || certificateClaimConverterModel.ChainValidationStatus == null)
            {
                result.ErrorList.Add(new Error
                {
                    ErrorCode = ErrorCodes.INVALID_CERTIFICATE,
                    ErrorMessage = "The certificate validation returned invalid data.",
                    StatusCode = ErrorHttpStatus.FORBIDDEN
                });

                return result;
            }

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

            return await Task.FromResult(result);
        }
    }
}