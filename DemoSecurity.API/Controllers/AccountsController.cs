using DemoSecurity.API.Data;
using DemoSecurity.Shared;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace DemoSecurity.API.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AccountsController : ControllerBase
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly UserManager<IdentityUser> userManager;
        private readonly IConfiguration configuration;

        public AccountsController(
            SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            IConfiguration configuration)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.configuration = configuration;
        }


        [HttpPost]
        [AllowAnonymous]
        [Route("register")]
        public async Task<IActionResult> Register(RegisterRequest registerRequest)
        {
            var identityUser = new IdentityUser
            {
                UserName = registerRequest.Email,
                Email = registerRequest.Email
            };

            var result = await userManager.CreateAsync(identityUser, registerRequest.Password);

            if(result.Succeeded == true)
            {
                return StatusCode(StatusCodes.Status201Created, new { result.Succeeded});
            } else
            {
                var errorsToReturn = "Registrazione fallita";
               foreach(var error in result.Errors)
                {  errorsToReturn += Environment.NewLine;
                   errorsToReturn += $"Codice di errore {error.Code}, {error.Description}";
                }
               return StatusCode(StatusCodes.Status500InternalServerError, errorsToReturn);
            }
        }

        [HttpPost]
        [Route("login")]
        [AllowAnonymous]    
        public async Task<IActionResult> Login(RegisterRequest user)
        {
            var signInResult = await signInManager.PasswordSignInAsync
                (user.Email, user.Password, false, false);

            if(signInResult.Succeeded == true)
            {
                var generaToken = new GeneraToken(configuration, userManager);
                var identityUser = await userManager.FindByEmailAsync(user.Email);
                if(identityUser == null) return Unauthorized(user);
                var token = await generaToken.GeneraJwtToken(identityUser);
                return Ok(token);
            } else
            {
                return Unauthorized(user);
            }
        }

    }
}
