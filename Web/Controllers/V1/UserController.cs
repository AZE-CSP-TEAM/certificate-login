using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Services.Services.UserServices;
using Web.Extensions;

namespace Web.Controllers.V1
{
    public class UserController : BaseV1Controller
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService) : base(userService) => _userService = userService;

        //[HttpPost]
        //[Route("getUsers")]
        //public async Task<IActionResult> GetUsers(GetUsersInput input) =>
        //  Result(await _userService.GetUsersAsync(input.Authorized(HttpContext)));
    }
}
