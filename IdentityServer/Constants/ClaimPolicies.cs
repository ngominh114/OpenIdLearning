using IdentityServer.Models;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServer.Constants
{
    public static class ClaimPolicies
    {
        public static readonly Dictionary<string, string[]> ClaimDestinationsMap = new()
        {
            [Claims.Name] = [Destinations.IdentityToken],
            [Claims.Email] = [Destinations.IdentityToken],
            [Claims.Role] = [Destinations.AccessToken, Destinations.IdentityToken],
            [LocalClaims.EmployeeId] = [Destinations.IdentityToken],
            [LocalClaims.CompanyName] = [Destinations.IdentityToken]
        };

        public static Dictionary<string, Func<ApplicationUser, IEnumerable<Claim>>> ScopeClaimMap = new()
        {
            ["profile"] = user =>
            [
                new(Claims.Name, user.UserName ?? string.Empty),
                new(Claims.Email, user.Email ?? string.Empty)
            ],

            ["employeeId"] = user => [new(LocalClaims.EmployeeId, user.EmployeeId ?? string.Empty)]
        };
    };

    

}
