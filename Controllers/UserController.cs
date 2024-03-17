using System.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using webAPIC_.Data;
using webAPIC_.Models;

namespace webAPIC_.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {
        private readonly UserDbContext _context;
        private readonly IConfiguration _configuration;

        public UserController(UserDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {

            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var ComputedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return ComputedHash.SequenceEqual(passwordHash);
            }
        }


        private string GenerateToken(User user)
        {
            string secretKey = _configuration.GetSection("AppSettings:SecretKey").Value;
            var claims = new[]
           {
            new Claim(ClaimTypes.Name, user.Name),
            new Claim(ClaimTypes.Email, user.Email),
        };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);



            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(7),
                SigningCredentials = credentials
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var token = tokenHandler.CreateToken(tokenDescriptor);
            var tokenString = tokenHandler.WriteToken(token);

            return tokenString;
        }


        [HttpGet]
        public async Task<ActionResult<List<User>>> Index()
        {
            return Ok(await _context.User.ToListAsync());
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<List<User>>> Find(int id)
        {

            var user = await _context.User.FindAsync(id);
            if (user == null)
            {
                return BadRequest("NotFound");
            }
            return Ok(user);
        }


        [HttpPost("login")]
        public async Task<ActionResult<List<User>>> login(User request, string password)
        {
            var user = await _context.User.FirstOrDefaultAsync(u => u.Email == request.Email); ;
            if (user == null)
            {
                return BadRequest("NotFound");
            }

            if (!VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("NotFound");
            }

            var token = GenerateToken(user);
            return Ok("User Os Valid , Token : " + token);
        }

        [HttpPost("register")]
        public async Task<ActionResult<List<User>>> Register(User user, string password)
        {
            CreatePasswordHash(password, out byte[] passwordHash, out byte[] passwordSalt);

            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;
            _context.User.Add(user);
            await _context.SaveChangesAsync();

            return Ok(await _context.User.ToListAsync());
        }


        [HttpPut]
        public async Task<ActionResult<List<User>>> Update(User request)
        {
            var user = await _context.User.FindAsync(request.UserId);
            if (user == null)
                return BadRequest("Not Found");


            user.Name = request.Name;
            user.Email = request.Email;

            await _context.SaveChangesAsync();

            return Ok(await _context.User.ToListAsync());
        }

        [HttpDelete]
        public async Task<IActionResult> Delete(int id)
        {
            var user = await _context.User.FindAsync(id);
            if (user == null)
                return BadRequest("Not Found");

            _context.User.Remove(user);

            await _context.SaveChangesAsync();
            return Ok(await _context.User.ToListAsync());
        }


    }
}
