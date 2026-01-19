using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client.AspNetCore;
using System.Security.Claims;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Controllers
{
    public class AuthenticationController : Controller
    {
        [HttpGet("~/signin-oidc/{provider}"), HttpPost("~/signin-oidc/{provider}"), IgnoreAntiforgeryToken]
        public async Task<ActionResult> LogInCallback()
        {
            // Retrieve the authorization data validated by OpenIddict as part of the callback handling.
            var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

            // Important: if the remote server doesn't support OpenID Connect and doesn't expose a userinfo endpoint,
            // result.Principal.Identity will represent an unauthenticated identity and won't contain any user claim.
            //
            // Such identities cannot be used as-is to build an authentication cookie in ASP.NET Core (as the
            // antiforgery stack requires at least a name claim to bind CSRF cookies to the user's identity) but
            // the access/refresh tokens can be retrieved using result.Properties.GetTokens() to make API calls.
            if (result.Principal is not ClaimsPrincipal { Identity.IsAuthenticated: true })
            {
                throw new InvalidOperationException("The external authorization data cannot be used for authentication.");
            }

            // Build an identity based on the external claims and that will be used to create the authentication cookie.
            var identity = new ClaimsIdentity(authenticationType: "ExternalLogin");

            // By default, OpenIddict will automatically try to map the email/name and name identifier claims from
            // their standard OpenID Connect or provider-specific equivalent, if available. If needed, additional
            // claims can be resolved from the external identity and copied to the final authentication cookie.
            foreach (var claim in result.Principal.Claims)
            {
                identity.SetClaim(claim.Type, claim.Value);
            }

            // Preserve the registration identifier to be able to resolve it later.
            identity.SetClaim(Claims.Private.RegistrationId, result.Principal.GetClaim(Claims.Private.RegistrationId));

            // Build the authentication properties based on the properties that were added when the challenge was triggered.
            var properties = new AuthenticationProperties(result.Properties!.Items)
            {
                RedirectUri = result.Properties.RedirectUri ?? "/"
            };

            // If needed, the tokens returned by the authorization server can be stored in the authentication cookie.
            //
            // To make cookies less heavy, tokens that are not used are filtered out before creating the cookie.
            properties.StoreTokens(result.Properties.GetTokens().Where(token => token.Name is
                // Preserve the access, identity and refresh tokens returned in the token response, if available.
                OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken or
                OpenIddictClientAspNetCoreConstants.Tokens.BackchannelIdentityToken or
                OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken));

            // Ask the default sign-in handler to return a new cookie and redirect the
            // user agent to the return URL stored in the authentication properties.
            //
            // For scenarios where the default sign-in handler configured in the ASP.NET Core
            // authentication options shouldn't be used, a specific scheme can be specified here.
            return SignIn(new ClaimsPrincipal(identity), properties);
        }
    }
}
