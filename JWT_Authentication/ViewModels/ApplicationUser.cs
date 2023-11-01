using Microsoft.AspNetCore.Identity;

namespace JWT_Authentication.ViewModels
{
    public class ApplicationUser : IdentityUser
    {
        public DateTime? LastLoginDate { get; set; }
    }
}
