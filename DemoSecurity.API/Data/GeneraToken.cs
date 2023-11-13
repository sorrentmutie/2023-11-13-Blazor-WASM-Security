using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DemoSecurity.API.Data
{
    public class GeneraToken : IGeneraToken
    {
        private readonly IConfiguration configuration;
        private readonly UserManager<IdentityUser> userManager;

        public GeneraToken(IConfiguration configuration, 
               UserManager<IdentityUser> userManager)
        {
            this.configuration = configuration;
            this.userManager = userManager;
        }
        public async Task<string> GeneraJwtToken(IdentityUser user)
        {
            var symmetricSecurityKey = new SymmetricSecurityKey
                (Encoding.UTF8.GetBytes(configuration["Jwt:Key"] ?? ""));

            var roles = await userManager.GetRolesAsync(user);

            var credentials = new SigningCredentials(
                symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>();

            if(roles != null)
            {
                foreach (var role in roles)
                {
                    claims.Add(new Claim(ClaimTypes.Role, role));   
                }
            }

            claims.Add(new Claim(ClaimTypes.Name, user.UserName!));
            claims.Add(new Claim(ClaimTypes.Email, user.Email!));
            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Email!));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

            var jwtSecurityToken = new JwtSecurityToken
                (configuration["Jwt:Issuer"], configuration["Jwt:Audience"],
                claims, DateTime.UtcNow, DateTime.UtcNow.AddMinutes(10),
                credentials);
            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

        }
    }
}
