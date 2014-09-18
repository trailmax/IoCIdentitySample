using IoCIdentity.Models;
using Microsoft.AspNet.Identity.EntityFramework;


namespace IoCIdentity.Identity
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext()
            : base("DefaultConnection", throwIfV1Schema: false)
        {
        }
    }
}