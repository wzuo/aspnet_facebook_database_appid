using System.Web.Mvc;
using Domain.Services;
using Microsoft.Owin.Security.Facebook;

namespace DatabaseFacebookProvider
{
    public class DatabaseFacebookAuthenticationOptions : FacebookAuthenticationOptions
    {
        /// <summary>
        /// Gets or sets the Facebook-assigned appId
        /// 
        /// </summary>
        new public static string AppId
        {
            get
            {
				//Call to your data source ex. database
				
                var siteService = DependencyResolver.Current.GetService<SiteService>();
                return siteService.SiteConfiguration.FacebookAppId;
            }
        }

        /// <summary>
        /// Gets or sets the Facebook-assigned app secret
        /// 
        /// </summary>
        new public static string AppSecret
        {
            get
            {
				//Call to your data source ex. database
				
                var siteService = DependencyResolver.Current.GetService<SiteService>();
                return siteService.SiteConfiguration.FacebookAppSecret;
            }
        } 
    }
}