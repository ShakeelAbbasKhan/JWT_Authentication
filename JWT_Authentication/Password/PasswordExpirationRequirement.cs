using Microsoft.AspNetCore.Authorization;

namespace JWT_Authentication.Password
{
    public class PasswordExpirationRequirement : IAuthorizationRequirement
    {
        public int DaysUntilPasswordExpiration { get; }

        public PasswordExpirationRequirement(int daysUntilPasswordExpiration)
        {
            DaysUntilPasswordExpiration = 5;
        }
    }
}
