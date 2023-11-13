using Microsoft.AspNetCore.Identity;

namespace DemoSecurity.API.Data
{
    public interface IGeneraToken
    {
        Task<string> GeneraJwtToken(IdentityUser user);
    }
}