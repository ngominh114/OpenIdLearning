using Azure.Core;
using IdentityServer.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Controllers
{
    [Route("connect")]
    public class AuthorizationController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;

        public AuthorizationController(UserManager<ApplicationUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpGet("authorize")]
        public async Task<IActionResult> Authorize()
        {
            var request = HttpContext.GetOpenIddictServerRequest()
                     ?? throw new InvalidOperationException("Invalid request.");

            // 1. Authenticate user via cookie
            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
            if (!result.Succeeded || result.Principal == null)
            {
                // Redirect to login page, carrying over parameters
                var props = new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                    Request.HasFormContentType ? Request.Form : Request.Query)
                };

                return Challenge(props, IdentityConstants.ApplicationScheme);
            }

            // 2. Consent screen (developer responsibility)
            //if (!await HasUserConsentedAsync(result.Principal, request.ClientId!, request.GetScopes()))
            //{
            //    // Pass request parameters to consent view
            //    return View("Consent", request);
            //}

            // 3. Build principal for OpenIddict
            var principal = CreateAuthorizationCodePrincipal(request, result.Principal);

            // 4. Hand off to OpenIddict → issues code + redirect
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        [HttpPost("consent")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> HandleConsent(string decision)
        {
            var request = HttpContext.GetOpenIddictServerRequest()
                         ?? throw new InvalidOperationException();

            var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
            if (!result.Succeeded || result.Principal == null)
            {
                return Challenge(IdentityConstants.ApplicationScheme);
            }

            if (decision == "deny")
            {
                // Return proper OAuth2 error with state
                return Forbid(
                    new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "User denied consent."
                    }),
                    OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
                );
            }

            var principal = CreateAuthorizationCodePrincipal(request, result.Principal);
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }


        private ClaimsPrincipal CreateAuthorizationCodePrincipal(OpenIddictRequest request, ClaimsPrincipal user)
        {
            var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType,
                                              Claims.Name, Claims.Role);

            identity.AddClaim(new Claim(Claims.Subject, user.FindFirstValue(ClaimTypes.NameIdentifier)!));
            identity.AddClaim(new Claim(Claims.Name, user.Identity!.Name ?? string.Empty));

            var principal = new ClaimsPrincipal(identity);

            // Carry over scopes/resources
            principal.SetScopes(request.GetScopes());
            principal.SetResources("api");

            return principal;
        }

    }
}
