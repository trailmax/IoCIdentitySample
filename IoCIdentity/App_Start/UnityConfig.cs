using System;
using System.Web;
using IoCIdentity.Identity;
using IoCIdentity.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using Microsoft.Practices.Unity;


namespace IoCIdentity
{
    public class UnityConfig
    {
        private static Lazy<IUnityContainer> container = new Lazy<IUnityContainer>(() =>
        {
            var container = new UnityContainer();
            RegisterTypes(container);
            return container;
        });

        public static IUnityContainer GetConfiguredContainer()
        {
            return container.Value;
        }


        private static void RegisterTypes(IUnityContainer container)
        {
            container.RegisterType<ApplicationDbContext>();
            container.RegisterType<ApplicationSignInManager>();
            container.RegisterType<ApplicationUserManager>();
            container.RegisterType<EmailService>();

            container.RegisterType<IAuthenticationManager>(
                new InjectionFactory(c => HttpContext.Current.GetOwinContext().Authentication));

            container.RegisterType<IUserStore<ApplicationUser>, UserStore<ApplicationUser>>(
                new InjectionConstructor(typeof(ApplicationDbContext)));
        }
    }
}
