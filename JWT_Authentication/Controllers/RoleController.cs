using JWT_Authentication.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JWT_Authentication.Controllers
{
    [Authorize(Policy = "SuperUserRights")]
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public RoleController(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
        }

        [HttpGet("GetRoles")]
        public IActionResult GetRoles()
        {
            var roles = _roleManager.Roles.ToList();
            var roleViewModels = new List<RoleViewModel>();

            foreach (var role in roles)
            {
                var roleViewModel = new RoleViewModel
                {
                    Id = role.Id,
                    RoleName = role.Name,
                    AssignedRoleCount = _userManager.GetUsersInRoleAsync(role.Name).Result.Count
                };

                roleViewModels.Add(roleViewModel);
            }

            return Ok(roleViewModels);
        }

        [HttpPost("CreateRole")]
        public async Task<IActionResult> CreateRole(IdentityRole model)
        {
            if (!string.IsNullOrEmpty(model.Name))
            {
                var role = new IdentityRole { Name = model.Name };
                var result = await _roleManager.CreateAsync(role);

                if (result.Succeeded)
                {
                    return CreatedAtAction("GetRole", new { id = role.Id }, role);
                }

                return BadRequest(result.Errors);
            }

            return BadRequest("Invalid model data");
        }

        [HttpGet("GetRole/{id}")]
        public async Task<IActionResult> GetRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
            {
                return NotFound("Role not found");
            }

            return Ok(role);
        }

        [HttpPut("UpdateRole/{id}")]
        public async Task<IActionResult> UpdateRole(string id, IdentityRole model)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
            {
                return NotFound("Role not found");
            }

            role.Name = model.Name;
            var result = await _roleManager.UpdateAsync(role);

            if (result.Succeeded)
            {
                return Ok("Role updated successfully");
            }

            return BadRequest(result.Errors);
        }

        [HttpDelete("DeleteRole/{id}")]
        public async Task<IActionResult> DeleteRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
            {
                return NotFound("Role not found");
            }

            var usersInRole = await _userManager.GetUsersInRoleAsync(role.Name);
            if (usersInRole.Any())
            {
                return BadRequest("This role cannot be deleted because it is assigned to one or more users.");
            }

            var result = await _roleManager.DeleteAsync(role);

            if (result.Succeeded)
            {
                return Ok("Role deleted successfully");
            }

            return BadRequest(result.Errors);
        }
    }
}
