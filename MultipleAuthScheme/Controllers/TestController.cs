using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace MultipleAuthScheme.Controllers
{
    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        public object Get()
        {
            return new
            {
                HttpContext.User.Identity.Name,
                Description = HttpContext.User.Identity.AuthenticationType == "COOKIE" ? "Accessing data using COOKIE Authentication" : "Accessing data using TOKEN Authentication"
            };
        }
    }
}
