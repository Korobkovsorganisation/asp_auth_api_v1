using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using asp_auth_api_v1.Models;

namespace AuthLab.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly TokenBlacklist _tokenBlacklist;

        public AuthController(
            UserManager<IdentityUser> userManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        public class TokenBlacklist
        {
            private readonly HashSet<string> _blacklistedTokens = new HashSet<string>();

            public void Add(string token)
            {
                _blacklistedTokens.Add(token);
            }

            public bool IsBlacklisted(string token)
            {
                return _blacklistedTokens.Contains(token);
            }
        }
        public class JwtMiddleware
        {
            private readonly RequestDelegate _next;
            private readonly TokenBlacklist _tokenBlacklist;

            public JwtMiddleware(RequestDelegate next, TokenBlacklist tokenBlacklist)
            {
                _next = next;
                _tokenBlacklist = tokenBlacklist;
            }

            public async Task Invoke(HttpContext context)
            {
                var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();

                if (!string.IsNullOrEmpty(token) && _tokenBlacklist.IsBlacklisted(token))
                {
                    context.Response.StatusCode = 401;
                    return;
                }

                await _next(context);
            }
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return BadRequest("User already exists!");

            IdentityUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return BadRequest(result.Errors);

            return Ok("User created successfully!");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null || !await _userManager.CheckPasswordAsync(user, model.Password))
                return Unauthorized();

            var authClaims = new List<Claim>
            {
                new(ClaimTypes.Name, user.UserName),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            var token = GetToken(authClaims);

            return Ok(new AuthResponse
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiration = token.ValidTo
            });
        }
        [HttpPost("logout")]
        public async Task<IActionResult> Logout(LogoutModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);

            if (user == null)
                return Unauthorized();

            var token = Request.Headers["Authorization"].ToString().Split(" ").Last();

            if (!string.IsNullOrEmpty(token))
            {
                _tokenBlacklist.Add(token);
            }

            return Ok(new { message = "User logged out successfully!" });
        }
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.Now.AddMinutes(
                    Convert.ToDouble(_configuration["Jwt:ExpireMinutes"])),
                claims: authClaims,
                signingCredentials: new SigningCredentials(
                    authSigningKey, SecurityAlgorithms.HmacSha256));

            return token;
        }
    }
}