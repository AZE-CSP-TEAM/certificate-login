using CertAuth.Controllers.V1;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Models.ServiceParameters.LoginParameters;
using Services.Services.CertificateValidationServices;
using System.Linq;
using System.Threading.Tasks;

namespace CertAuth.Controllers
{

    public class CertificateController : BaseV1Controller
    {
        private readonly ICertificateValidationService _certificateValidationService;

        public CertificateController(ICertificateValidationService certificateValidationService) :
            base(certificateValidationService) => _certificateValidationService = certificateValidationService;

        [HttpGet]
        [Authorize]
        [Route("login")]
        public async Task<IActionResult> Login(string origin) => Result(await _certificateValidationService.Login(new CertificateLoginInput
        {
            Origin = origin,
            Claims = Request.HttpContext.User.Claims.ToList()
        }));
    }
}
