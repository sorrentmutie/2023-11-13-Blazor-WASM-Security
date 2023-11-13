using Blazored.LocalStorage;
using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace DemoSecurity.WASM.Security;

public class MyAppAuthenticationProvider : AuthenticationStateProvider
{
    private readonly ILocalStorageService localStorage;
    private JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

    public MyAppAuthenticationProvider(ILocalStorageService localStorage)
    {
        this.localStorage = localStorage;
    }


    public void SignOut()
    {
        ClaimsPrincipal nessuno = new ClaimsPrincipal(new ClaimsIdentity());
        var authState = Task.FromResult(new AuthenticationState(nessuno));
        NotifyAuthenticationStateChanged(authState);
    }

    public async Task SignIn()
    {
        var token = await localStorage.GetItemAsync<string>("jwtToken");
        var state = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        if (string.IsNullOrEmpty(token))
        {
            state =  new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        var jwtToken = jwtSecurityTokenHandler.ReadJwtToken(token);
        DateTime? expires = jwtToken.ValidTo;

        if (expires.HasValue && expires > DateTime.UtcNow)
        {
            var claims = jwtToken.Claims.ToList();
            var identity = new ClaimsPrincipal(
                new ClaimsIdentity(claims, "jwt"));
            state =  new AuthenticationState(identity);

        }
        else
        {
            await localStorage.RemoveItemAsync("jwtToken");
            state = new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }

        var authState = Task.FromResult(state);
        NotifyAuthenticationStateChanged(authState);
    }



    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
		try
		{
			var token = await localStorage.GetItemAsync<string>("jwtToken");

            if(string.IsNullOrEmpty(token))
            {
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            var jwtToken = jwtSecurityTokenHandler.ReadJwtToken(token);
            DateTime? expires = jwtToken.ValidTo;

            if(expires.HasValue && expires > DateTime.Now)
            {
                var claims = jwtToken.Claims.ToList();
                var identity = new ClaimsPrincipal(
                    new ClaimsIdentity(claims, "jwt"));
                return new AuthenticationState(identity);

            }
            else
            {
                await localStorage.RemoveItemAsync("jwtToken");
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }


        }
		catch (Exception ex)
		{

            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
        }
    }
}
