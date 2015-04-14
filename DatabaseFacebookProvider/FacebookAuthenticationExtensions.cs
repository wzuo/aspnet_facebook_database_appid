using System;
using Owin;

namespace DatabaseFacebookProvider
{
    public static class FacebookAuthenticationExtensions
    {
        public static IAppBuilder UseDatabaseFacebookAuthentication(this IAppBuilder app, DatabaseFacebookAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(DatabaseFacebookAuthenticationMiddleware), app, options);

            return app;
        }
    }
}