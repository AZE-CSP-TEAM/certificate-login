﻿using CertAuth.Helpers;
using Microsoft.AspNetCore.Mvc;
using Models;
using Services.Services;
using System;

namespace CertAuth.Controllers
{
    [ApiController]
    public class BaseController : ControllerBase
    {
        // implementation
        private readonly IService _service;
        public BaseController(IService service) => _service = service;
        public BaseController() { }
        public CreateActionResult<TResult> Result<TResult>(ContainerResult<TResult> result)
            => new CreateActionResult<TResult>(result);
    }
}
