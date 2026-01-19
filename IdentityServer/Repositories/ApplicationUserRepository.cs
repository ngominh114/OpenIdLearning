using IdentityServer.Data;
using IdentityServer.Models;
using Microsoft.EntityFrameworkCore;

namespace IdentityServer.Repositories
{
    public interface IApplicationUserRepository
    {
        public Task<ApplicationUser?> GetUserByEmployeeIdAsync(string employeeId);
    }

    public class ApplicationUserRepository : IApplicationUserRepository
    {
        private readonly ApplicationDbContext _dbContext;

        public ApplicationUserRepository(ApplicationDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public Task<ApplicationUser?> GetUserByEmployeeIdAsync(string employeeId)
        {
            return _dbContext.Users.SingleOrDefaultAsync(u => u.EmployeeId == employeeId);
        }
    }
}
