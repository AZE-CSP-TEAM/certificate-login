using Microsoft.AspNetCore.Mvc;
using Services.Services;

namespace Web.Controllers.V1
{
    /// <summary>
    /// 
    /// </summary>
    [Route("api/v1/[controller]")]
    public class BaseV1Controller : BaseController
    {
        public BaseV1Controller(IService service) : base(service) { }
        public BaseV1Controller() { }
    }
}
