using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Services.Services;

namespace CertAuth.Controllers.V1
{
    /// <summary>
    /// 
    /// </summary>
    [Route("api/v1/[controller]")]
    [ApiController]
    public class BaseV1Controller : BaseController
    {
        public BaseV1Controller(IService service) : base(service) { }
        public BaseV1Controller() { }
        public AuthorizationFilterContext context;
    }
}
