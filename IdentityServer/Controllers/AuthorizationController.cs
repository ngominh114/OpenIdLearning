using IdentityServer.Constants;
using IdentityServer.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
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
        private readonly IOpenIddictScopeManager _scopeManager;

        public AuthorizationController(UserManager<ApplicationUser> userManager, IOpenIddictScopeManager scopeManager)
        {
            _userManager = userManager;
            _scopeManager = scopeManager;
        }

        [HttpGet("authorize")]
        [HttpPost("authorize")]
        [IgnoreAntiforgeryToken]
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
            var principal = await CreateAuthorizationCodePrincipal(request, result.Principal);

            // 4. Hand off to OpenIddict → issues code + redirect
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        //[HttpPost("consent")]
        //[ValidateAntiForgeryToken]
        //public async Task<IActionResult> HandleConsent(string decision)
        //{
        //    var request = HttpContext.GetOpenIddictServerRequest()
        //                 ?? throw new InvalidOperationException();

        //    var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);
        //    if (!result.Succeeded || result.Principal == null)
        //    {
        //        return Challenge(IdentityConstants.ApplicationScheme);
        //    }

        //    if (decision == "deny")
        //    {
        //        // Return proper OAuth2 error with state
        //        return Forbid(
        //            new AuthenticationProperties(new Dictionary<string, string?>
        //            {
        //                [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.AccessDenied,
        //                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "User denied consent."
        //            }),
        //            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme
        //        );
        //    }

        //    var principal = await CreateAuthorizationCodePrincipal(request, result.Principal);
        //    return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        //}

        [HttpGet("endsession")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            return SignOut(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = "/"
                }
            );
        }

        private async Task<ClaimsPrincipal> CreateAuthorizationCodePrincipal(OpenIddictRequest request, ClaimsPrincipal userPrincipal)
        {
            var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType,
                                              Claims.Name, Claims.Role);
            var localUser = await _userManager.GetUserAsync(userPrincipal) ?? throw new InvalidOperationException("User not found.");
            identity.AddClaim(new Claim(Claims.Subject, localUser.Id));

            foreach (var scope in request.GetScopes())
            {
                if (ClaimPolicies.ScopeClaimMap.TryGetValue(scope, out var claimFactory))
                {
                    foreach (var claim in claimFactory(localUser))
                    {
                        identity.AddClaim(claim);
                    }
                }
            }

            // Apply destinations
            identity.SetDestinations(claim =>
            {
                return ClaimPolicies.ClaimDestinationsMap.TryGetValue(claim.Type, out var destinations)
                    ? destinations
                    : [];
            });

            var principal = new ClaimsPrincipal(identity);

            // Carry over scopes/resources
            principal.SetScopes(request.GetScopes());
            var resources = _scopeManager.ListResourcesAsync(principal.GetScopes()).ToBlockingEnumerable();
            principal.SetResources(resources);

            return principal;
        }

    }
}
