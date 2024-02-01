using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using System.Net;
using Common;
using Common.Enums.ErrorEnums;
using Common.Resources;
using Web.Helpers;
using Services.Services.UserServices;
using Models;
using System.Threading.Tasks;
using log4net;
using System.Reflection;
using Web.Extensions;

namespace Web.Filters
{
    public class ClaimAuthorize : Attribute, IAsyncAuthorizationFilter
    {
        private readonly ILog _logger;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        private ClaimAuthorize() => LogManager.GetLogger(MethodBase.GetCurrentMethod().DeclaringType);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        private ClaimAuthorize(ILog logger) => _logger = logger;

        public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            //try
            //{
            //    _logger.Info($"Executing process started from this class : {GetType()}");

            //    ContainerResult<bool> result = await context.HttpContext.RequestServices.GetService<IUserService>().AuthorizationAsync(new AuthorizationInput
            //    {
            //    }.Authorized(context.HttpContext));

            //    if (!result.Output)
            //    {
            //        context.Result = new CreateActionResult<bool>(result);

            //        _logger.Error($"Error occured from this class : {GetType()} : {result.ErrorList[0].ErrorMessage}");
            //    }

            //    _logger.Info($"Executing process finished from this class : {GetType()}");
            //}
            //catch (Exception ex)
            //{
            //    context.Result = new CreateActionResult<bool>(new ContainerResult<bool>
            //    {
            //        ErrorList = new List<Error>
            //          {
            //             new Error
            //             {
            //                 ErrorCode = ErrorCodes.INTERNAL_ERROR,
            //                 StatusCode = ErrorHttpStatus.INTERNAL,
            //                 ErrorMessage = Resource.UNHANDLED_EXCEPTION
            //             }
            //          }
            //    })
            //    {
            //        StatusCode = (int)HttpStatusCode.Unauthorized
            //    };

            //    _logger.Error($"Error occured from this class : {GetType()} : {ex}");
            //}
        }
    }
}
