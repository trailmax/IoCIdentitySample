using System;
using System.Collections.Generic;
using System.Linq;
using IoCIdentity.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security.DataProtection;


namespace IoCIdentity.Identity
{
    public class ApplicationUserManager : UserManager<ApplicationUser>
    {
        private readonly ApplicationDbContext context;

        public ApplicationUserManager(IUserStore<ApplicationUser> store, IIdentityMessageService emailService, IDataProtectionProvider dataProtectionProvider, ApplicationDbContext context) : base(store)
        {
            this.context = context;
            // Configure validation logic for usernames
            this.UserValidator = new UserValidator<ApplicationUser>(this)
            {
                AllowOnlyAlphanumericUserNames = false,
                RequireUniqueEmail = true
            };

            // Configure validation logic for passwords
            this.PasswordValidator = new PasswordValidator
            {
                RequiredLength = 6,
                RequireNonLetterOrDigit = false,
                RequireDigit = false,
                RequireLowercase = false,
                RequireUppercase = false,
            };

            // Configure user lockout defaults
            this.UserLockoutEnabledByDefault = true;
            this.DefaultAccountLockoutTimeSpan = TimeSpan.FromMinutes(5);
            this.MaxFailedAccessAttemptsBeforeLockout = 5;

            // Register two factor authentication providers. This application uses Phone and Emails as a step of receiving a code for verifying the user
            // You can write your own provider and plug it in here.
            this.RegisterTwoFactorProvider("Phone Code", new PhoneNumberTokenProvider<ApplicationUser>
            {
                MessageFormat = "Your security code is {0}"
            });
            this.RegisterTwoFactorProvider("Email Code", new EmailTokenProvider<ApplicationUser>
            {
                Subject = "Security Code",
                BodyFormat = "Your security code is {0}"
            });
            this.EmailService = emailService;
            this.SmsService = new SmsService();

            if (dataProtectionProvider != null)
            {
                IDataProtector dataProtector = dataProtectionProvider.Create("ASP.NET Identity");

                this.UserTokenProvider = new DataProtectorTokenProvider<ApplicationUser>(dataProtector);
            }

            //alternatively use this if you are running in Azure Web Sites
            this.UserTokenProvider = new EmailTokenProvider<ApplicationUser, string>();
        }

        /// the create part which is moved from the default /// 
        public IEnumerable<ApplicationUser> GetUsersInRole(string roleName)
        {
            if (String.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentNullException(nameof(roleName));
            }

            var role = context.Roles.FirstOrDefault(r => r.Name == roleName);

            if (role == null)
            {
                throw new Exception($"Role with this name not found: {roleName}");
            }

            var users = context.Users.Where(u => u.Roles.Any(r => r.RoleId == role.Id)).ToList();

            return users;
        }
    }
}