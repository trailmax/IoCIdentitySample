using System.Linq;
using System.Web.Mvc;
using IoCIdentity;
using Microsoft.Practices.Unity.Mvc;

[assembly: WebActivatorEx.PreApplicationStartMethod(typeof(UnityWebActivator), "Start")]
[assembly: WebActivatorEx.ApplicationShutdownMethod(typeof(UnityWebActivator), "Shutdown")]

namespace IoCIdentity
{
    public static class UnityWebActivator
    {
        public static void Start() 
        {
            var container = UnityConfig.GetConfiguredContainer();

            FilterProviders.Providers.Remove(FilterProviders.Providers.OfType<FilterAttributeFilterProvider>().First());
            FilterProviders.Providers.Add(new UnityFilterAttributeFilterProvider(container));

            DependencyResolver.SetResolver(new UnityDependencyResolver(container));

            // TODO: Uncomment if you want to use PerRequestLifetimeManager
            // Microsoft.Web.Infrastructure.DynamicModuleHelper.DynamicModuleUtility.RegisterModule(typeof(UnityPerRequestHttpModule));
        }

        public static void Shutdown()
        {
            var container = UnityConfig.GetConfiguredContainer();
            container.Dispose();
        }
    }
}