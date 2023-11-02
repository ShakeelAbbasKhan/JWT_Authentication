using JWT_Authentication.ViewModels;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace JWT_Authentication.Middleware
{
    public class RefreshTokenValidationMiddleware : IActionFilter
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public RefreshTokenValidationMiddleware(UserManager<ApplicationUser> userManager, IHttpContextAccessor httpContextAccessor)
        {
            _userManager = userManager;
            _httpContextAccessor = httpContextAccessor;
        }

        public void OnActionExecuting(ActionExecutingContext context)
        {
            string authorizationHeader = context.HttpContext.Request.Headers["Authorization"];
            if (string.IsNullOrWhiteSpace(authorizationHeader) || !authorizationHeader.StartsWith("Bearer "))
            {
                context.HttpContext.Response.StatusCode = 401;
                context.Result = new Microsoft.AspNetCore.Mvc.JsonResult("Unauthorized");
                return;
            }

            string refreshToken = authorizationHeader.Substring("Bearer ".Length).Trim();

            if (IsLoginPath(_httpContextAccessor.HttpContext.Request.Path))
            {
                return;
            }

            if (context.HttpContext.User?.Identity?.Name != null)
            {
                ApplicationUser user = _userManager.FindByNameAsync(context.HttpContext.User.Identity.Name).Result;
                if (user == null || user.RefreshToken != refreshToken)
                {
                    context.HttpContext.Response.StatusCode = 401;
                    context.Result = new Microsoft.AspNetCore.Mvc.JsonResult("Unauthorized");
                    return;
                }
            }
            else
            {
                context.HttpContext.Response.StatusCode = 401; 
                context.Result = new Microsoft.AspNetCore.Mvc.JsonResult("Unauthorized");
            }
        }

        public void OnActionExecuted(ActionExecutedContext context)
        {
        }

        private bool IsLoginPath(PathString path)
        {
            return path.Equals("/api/Account/Login");
        }
    }
}
