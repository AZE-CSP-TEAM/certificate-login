using Models;
using Models.ServiceParameters.LoginParameters;
using System.Threading.Tasks;

namespace Services.Services.CertificateValidationServices
{
    public interface ICertificateValidationService : IService
    {
        Task<ContainerResult<string>> Login(CertificateLoginInput input);
        Task<ContainerResult<ValidateCertificateOutput>> ValidateCertificate(ValidateCertificateInput input);
    }
}
