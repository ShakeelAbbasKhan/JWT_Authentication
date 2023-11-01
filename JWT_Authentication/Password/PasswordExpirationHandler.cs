using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace JWT_Authentication.Password
{
    public class PasswordExpirationHandler : AuthorizationHandler<PasswordExpirationRequirement>
    {
        protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        PasswordExpirationRequirement requirement)
        {
            var user = context.User;

            if (user != null)
            {
                var lastLoginDate = user.FindFirstValue("LastLoginDate");

                if (!string.IsNullOrEmpty(lastLoginDate) && DateTime.TryParse(lastLoginDate, out var loginDate))
                {
                    var daysSinceLastLogin = (DateTime.Now - loginDate).Days;

                    if (daysSinceLastLogin >= requirement.DaysUntilPasswordExpiration)
                    {
                        context.Fail();
                    }
                }
            }

            context.Succeed(requirement);
            return Task.CompletedTask;
        }
    }
}
