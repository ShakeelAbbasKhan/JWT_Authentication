using JWT_Authentication.AuthServiceRepository;
using JWT_Authentication.Helper;
using JWT_Authentication.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace JWT_Authentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<AccountController> _logger;
        private readonly JWTService _jWTService;
        private readonly IAuthService _authService;
        private readonly IConfiguration _configuration;

        public AccountController(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager, ILogger<AccountController> logger, JWTService jWTService, IAuthService authService, IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _jWTService = jWTService;
            _authService = authService;
            _configuration = configuration;
        }


        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            TokenViewModel _TokenViewModel = new();
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null && user.LastLoginDate.HasValue)
                {
                    DateTime lastLoginDate = user.LastLoginDate.Value; // Convert to DateTime
                    if (lastLoginDate.AddDays(5) < DateTime.UtcNow)
                    {
                        return Ok("Password Expires Reset the Password");
                    }
                }

                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, true);
                if (result.Succeeded)
                {
                    var userRoles = await _userManager.GetRolesAsync(user);
                    var authClaims = new List<Claim>
                    {
                       new Claim(ClaimTypes.Name, user.UserName),
                       new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    };


                    foreach (var userRole in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                    }
                    _TokenViewModel.AccessToken = _jWTService.GenerateToken(authClaims);
                    _TokenViewModel.RefreshToken = _authService.GenerateRefreshToken();
                    _TokenViewModel.StatusCode = 1;
                    _TokenViewModel.StatusMessage = "Success";

                    var _RefreshTokenValidityInDays = Convert.ToInt64(_configuration["JWTKey:RefreshTokenValidityInDays"]);
                    user.RefreshToken = _TokenViewModel.AccessToken;
                    user.RefreshTokenExpiryTime = DateTime.Now.AddDays(_RefreshTokenValidityInDays);
                    await _userManager.UpdateAsync(user);


                    return Ok(new { _TokenViewModel });

                }

                if (result.IsLockedOut)
                {
                    var lockoutEndDate = await _userManager.GetLockoutEndDateAsync(user);
                    return BadRequest($"Your account is locked out until {lockoutEndDate}.");
                }

                return BadRequest("Invalid login attempt");
            }

            return BadRequest(ModelState);
        }


        [Authorize(Policy = "SuperUserRights")]
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterViewModel registerModel)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser
                {
                    UserName = registerModel.Email,
                    Email = registerModel.Email,
                    LastLoginDate = DateTime.Now,
                };

                var result = await _userManager.CreateAsync(user, registerModel.Password);
                if (result.Succeeded)
                {
                    await _userManager.AddToRoleAsync(user, registerModel.RoleName);
     
                    return Ok("Registration successful");
                }

                return BadRequest(result.Errors);
            }

            return BadRequest(ModelState);
        }


        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            Response.Cookies.Delete("token");
            return Ok("Logged out successfully");
        }

     //   [Authorize(Policy = "SuperUserRights")]
        [HttpGet("userlist")]
        public IActionResult UserList()
        {
            var users = _userManager.Users.Select(u => new UserListVM
            {
                Id = u.Id,
                Email = u.Email,
                Roles = _userManager.GetRolesAsync(u).Result.ToList()
            }).ToList();

            return Ok(users);
        }


        [HttpPost("forgotpassword")]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);

                    var passwordResetLink = Url.Action("ResetPassword", "Account",
                        new { email = model.Email, token = token }, Request.Scheme);

                    _logger.Log(LogLevel.Warning, passwordResetLink);

                    return Ok( new {token });
                }
                return NotFound("User not found");
            }

            return BadRequest(ModelState);
        }

        [HttpPost("resetpassword")]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
                    if (result.Succeeded)
                    {
                        user.LockoutEnd = null;
                        user.LastLoginDate = DateTime.Now;

                        await _userManager.UpdateAsync(user);

                        return Ok("Password reset successful");
                    }
                    return BadRequest(result.Errors);
                }

                return NotFound("User not found");
            }

            return BadRequest(ModelState);
        }

        [Authorize(Policy = "SuperUserRights")]

        [HttpGet("Hello")]

        public IActionResult Hello()
        {
            return Ok("heelo");
        }

    }
}
