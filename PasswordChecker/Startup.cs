using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(PasswordChecker.Startup))]
namespace PasswordChecker
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
