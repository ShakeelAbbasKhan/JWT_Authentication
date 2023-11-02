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

        [HttpGet("GetStudents")]
        public async Task<IActionResult> GetStudents()
        {
            var categoryList = await _db.Students.ToListAsync();
            return Ok(categoryList);
        }

        [HttpGet("GetStudent/{id}")]
        public async Task<IActionResult> GetStudent(int id)
        {
            var category = await _db.Students.FirstOrDefaultAsync(x => x.Id == id);
            if (category == null)
            {
                return NotFound();
            }
            return Ok(category);
        }

        [HttpPost("CreateStudent")]
        public async Task<IActionResult> CreateStudent(Student obj)
        {
          
            if (ModelState.IsValid)
            {
                _db.Students.Add(obj);
                await _db.SaveChangesAsync();
                return Ok("Student Created Successfully");
            }

            return BadRequest(ModelState);
        }

        [HttpPut("UpdateStudent/{id}")]
        public async Task<IActionResult> UpdateStudent(int id, Student obj)
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

        [HttpDelete("DeleteStudent/{id}")]
        public async Task<IActionResult> DeleteStudent(int id)
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
