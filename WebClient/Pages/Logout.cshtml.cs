using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebClient.Pages
{
    public class LogoutModel : PageModel
    {
        public void OnGet()
        {
            SignOut(CookieAuthenticationDefaults.AuthenticationScheme, "IdentityScheme");
        }
    }
}
