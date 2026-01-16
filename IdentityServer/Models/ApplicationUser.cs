using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? EmployeeId { get; set; }
        public string? CompanyName { get; set; }
    }
}
