using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace DemoSecurity.WASM.Security;

public class MyAppAuthenticationProvider : AuthenticationStateProvider
{
    private readonly ILocalStorageService localStorage;
    private readonly HttpClient httpClient;
    private JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

    public MyAppAuthenticationProvider(ILocalStorageService localStorage, HttpClient httpClient)
    {
        this.localStorage = localStorage;
        this.httpClient = httpClient;
    }


    public void SignOut()
    {
        ClaimsPrincipal nobody = new ClaimsPrincipal(new ClaimsIdentity());
        Task<AuthenticationState> authentication =
            Task.FromResult(new AuthenticationState(nobody));
        NotifyAuthenticationStateChanged(authentication);
    }

    public async Task SignIn()
    {
        string savedToken = await localStorage.GetItemAsStringAsync("jwtToken");
        JwtSecurityToken jwtSecurityToken = jwtSecurityTokenHandler.ReadJwtToken(
           savedToken);
        IList<Claim> claims = jwtSecurityToken.Claims.ToList();
        claims.Add(new Claim(ClaimTypes.Name, jwtSecurityToken.Subject));
        var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));
        Task<AuthenticationState> authentication =
            Task.FromResult(new AuthenticationState(user));
        NotifyAuthenticationStateChanged(authentication);
    }


    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {

        try
        {
            string savedToken = await localStorage.GetItemAsync<string>
                ("jwtToken");
            if (string.IsNullOrWhiteSpace(savedToken))
            {
                return new AuthenticationState(
                new ClaimsPrincipal(
                    new ClaimsIdentity()));
            }

            JwtSecurityToken jwtSecurityToken =
                jwtSecurityTokenHandler.ReadJwtToken(savedToken);
            DateTime expires = jwtSecurityToken.ValidTo;
            if (expires < DateTime.UtcNow)
            {
                await localStorage.RemoveItemAsync("jwtToken");
                return new AuthenticationState(
                new ClaimsPrincipal(
                    new ClaimsIdentity()));
            }

            IList<Claim> claims = jwtSecurityToken.Claims.ToList();
            claims.Add(new Claim(ClaimTypes.Name, jwtSecurityToken.Subject));

            var user = new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt"));
            return new AuthenticationState(user);

        }
        catch (Exception)
        {
            return new AuthenticationState(
                new ClaimsPrincipal(
                    new ClaimsIdentity()));
        }
    }
}
