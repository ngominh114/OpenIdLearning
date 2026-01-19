using IdentityServer.Models;
using IdentityServer.Repositories;
using Microsoft.AspNetCore.Identity;

namespace IdentityServer.Validators
{
    public class ApplicationUserValidator(IApplicationUserRepository applicationUserRepository) : UserValidator<ApplicationUser>
    {
        public override async Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user)
        {
            List<IdentityError> errors = [];
            var emailAndUserNameValidationTask = base.ValidateAsync(manager, user);
            var employeeValidationTask = ValidateEmployeeInformation(user);

            await Task.WhenAll(emailAndUserNameValidationTask, employeeValidationTask);

            errors.AddRange((await emailAndUserNameValidationTask).Errors);
            errors.AddRange(await employeeValidationTask);
            return errors.Count > 0 ? IdentityResult.Failed([.. errors]) : IdentityResult.Success;
        }

        private async Task<List<IdentityError>> ValidateEmployeeInformation(ApplicationUser user)
        {
            List<IdentityError> errors = [];
            if (!string.IsNullOrEmpty(user.EmployeeId))
            {
                var existingUser = await applicationUserRepository.GetUserByEmployeeIdAsync(user.EmployeeId);
                if (existingUser != null)
                {
                    errors.Add(new IdentityError()
                    {
                        Code = "EmployeeId Exist",
                        Description = $"User with Employee Id \"{user.EmployeeId}\" already exist"
                    });
                }
            }
            return errors;
        }
    }
}
