using Microsoft.AspNetCore.Mvc;

namespace CertAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get()
        {
            return Ok("Application is running successfully!");
        }
    }

}
