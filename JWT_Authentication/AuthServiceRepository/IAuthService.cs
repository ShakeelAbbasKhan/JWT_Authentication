using JWT_Authentication.ViewModels;

namespace JWT_Authentication.AuthServiceRepository
{
    public interface IAuthService
    {
        Task<TokenViewModel> GetRefreshToken(GetRefreshTokenViewModel model);
        string GenerateRefreshToken();
    }
}
