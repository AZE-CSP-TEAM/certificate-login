using Microsoft.AspNetCore.Mvc;
using Models;
using Services.Services;
using System;
using Web.Helpers;

namespace Web.Controllers
{
    [ApiController]
    public class BaseController : ControllerBase, IDisposable
    {
        private readonly IService _service;
        public BaseController(IService service) => _service = service;
        public BaseController() { }
        public CreateActionResult<TResult> Result<TResult>(ContainerResult<TResult> result)
            => new CreateActionResult<TResult>(result);

        #region Disposable Members
        public void Dispose() => _service?.Dispose();
        #endregion
    }
}
