using JWT_Authentication.Model;
using JWT_Authentication.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JWT_Authentication.Controllers
{
    [Authorize(Roles = "Admin, User")]
    [Route("api/[controller]")]
    [ApiController]
    public class StudentController : ControllerBase
    {
        private readonly ApplicationDbContext _db;

        public StudentController(ApplicationDbContext db)
        {
            _db = db;
        }

        [HttpGet("GetCategories")]
        public async Task<IActionResult> GetCategories()
        {
            var categoryList = await _db.Students.ToListAsync();
            return Ok(categoryList);
        }

        [HttpGet("GetCategory/{id}")]
        public async Task<IActionResult> GetCategory(int id)
        {
            var category = await _db.Students.FirstOrDefaultAsync(x => x.Id == id);
            if (category == null)
            {
                return NotFound();
            }
            return Ok(category);
        }

        [HttpPost("CreateCategory")]
        public async Task<IActionResult> CreateCategory(Student obj)
        {
          
            if (ModelState.IsValid)
            {
                _db.Students.Add(obj);
                await _db.SaveChangesAsync();
                return Ok("Student Created Successfully");
            }

            return BadRequest(ModelState);
        }

        [HttpPut("UpdateCategory/{id}")]
        public async Task<IActionResult> UpdateCategory(int id, Student obj)
        {
            if (id != obj.Id)
            {
                return BadRequest();
            }

            if (ModelState.IsValid)
            {
                _db.Entry(obj).State = EntityState.Modified;
                await _db.SaveChangesAsync();
                return Ok("Student Updated Successfully");
            }

            return BadRequest(ModelState);
        }

        [HttpDelete("DeleteCategory/{id}")]
        public async Task<IActionResult> DeleteCategory(int id)
        {
            var category = await _db.Students.FindAsync(id);
            if (category == null)
            {
                return NotFound();
            }

            _db.Students.Remove(category);
            await _db.SaveChangesAsync();
            return Ok("Student Deleted Successfully");
        }

    }
}
