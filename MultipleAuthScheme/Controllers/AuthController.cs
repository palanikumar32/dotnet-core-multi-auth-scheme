using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using MultipleAuthScheme.Models;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace MultipleAuthScheme.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        public AuthController(IConfiguration configuration)
        {
            _config = configuration;
        }

        public async Task<AuthenticationResult> Login([FromForm] string userName, [FromForm] string password, [FromHeader] string authmode = "")
        {
            if (userName != "demo" || password != "demo")
                return new AuthenticationResult { HasError = true, Message = "Either the user name or password is incorrect." };

            var claims = new Claim[]
            {
                new Claim(ClaimTypes.Name, userName)
            };
            

            if(authmode?.ToLower() == "token")
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_config.GetValue<string>("JWTSecret"));
                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(claims, "JWT"),
                    Expires = DateTime.UtcNow.AddMinutes(_config.GetValue<int>("JWTExpiry")),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                };
                var token = tokenHandler.CreateToken(tokenDescriptor);
                var jwt = tokenHandler.WriteToken(token);
                return new AuthenticationResult { Token = jwt };
            }
            else
            {
                ClaimsPrincipal princ = new ClaimsPrincipal(new ClaimsIdentity(claims, "COOKIE"));
                await HttpContext.SignInAsync(princ);
                return new AuthenticationResult();
            }
        }
    }
}
