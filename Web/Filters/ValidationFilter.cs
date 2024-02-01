using Microsoft.AspNetCore.Mvc.Filters;
using System.Collections.Generic;
using System.Linq;
using Common;
using Common.Enums.ErrorEnums;
using Common.Resources;
using Web.Helpers;
using Models;

namespace Web.Filters
{
	public class ValidationFilter : IActionFilter
	{
		public void OnActionExecuted(ActionExecutedContext context) { }

		/// <summary>
		/// 
		/// </summary>
		/// <param name="context"></param>
		public void OnActionExecuting(ActionExecutingContext context)
		{
			if (context.ActionArguments.Any(x => x.Value == null))
			{
				context.Result = new CreateActionResult<string>(new ContainerResult<string>()
				{
					ErrorList = new List<Error>
					{
						new Error
						{
							ErrorCode = ErrorCodes.INPUT_IS_NOT_VALID,
							ErrorMessage = Resource.INVALID_INPUT,
							StatusCode = ErrorHttpStatus.BADREQUEST
						}
					}
				});
				return;
			}

			if (context.ModelState.IsValid) return;

			context.Result = new CreateActionResult<string>(new ContainerResult<string>()
			{
				ErrorList = context.ModelState.Select(keyValuePair => new Error
				{
					ErrorCode = ErrorCodes.INPUT_IS_NOT_VALID,
					ErrorMessage = keyValuePair.Value.Errors.FirstOrDefault(x => x.ErrorMessage != string.Empty)?.ErrorMessage ?? Resource.INVALID_INPUT,
					StatusCode = ErrorHttpStatus.BADREQUEST
				}).ToList()
			});
		}
	}
}
