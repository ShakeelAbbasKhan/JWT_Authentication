using JWT_Authentication.ViewModels;

namespace JWT_Authentication.AuthServiceRepository
{
    public interface IAuthService
    {
        Task<TokenViewModel> Login(LoginViewModel model);
        Task<TokenViewModel> GetRefreshToken(GetRefreshTokenViewModel model);
        string GenerateRefreshToken();
    }
}
