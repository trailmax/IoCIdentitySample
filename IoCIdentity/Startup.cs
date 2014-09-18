using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(IoCIdentity.Startup))]
namespace IoCIdentity
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
