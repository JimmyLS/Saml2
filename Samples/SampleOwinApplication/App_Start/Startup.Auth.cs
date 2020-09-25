using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using SampleOwinApplication.Models;
using Sustainsys.Saml2;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Owin;
using Sustainsys.Saml2.Saml2P;
using Sustainsys.Saml2.WebSso;
using System;
using System.Configuration;
using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Web.Hosting;
using System.Diagnostics;

namespace SampleOwinApplication
{
	public partial class Startup
    {
        // For more information on configuring authentication, please visit http://go.microsoft.com/fwlink/?LinkId=301864
        public void ConfigureAuth(IAppBuilder app)
        {
            // Configure the db context, user manager and signin manager to use a single instance per request
            app.CreatePerOwinContext(ApplicationDbContext.Create);
            app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
            app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

            // Enable the application to use a cookie to store information for the signed in user
            // and to use a cookie to temporarily store information about a user logging in with a third party login provider
            // Configure the sign in cookie
            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                LoginPath = new PathString("/Account/Login"),
                Provider = new CookieAuthenticationProvider
                {
                    // Enables the application to validate the security stamp when the user logs in.
                    // This is a security feature which is used when you change a password or add an external login to your account.  
                    OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                        validateInterval: TimeSpan.FromMinutes(30),
                        regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
                }
            });
            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.UseSaml2Authentication(CreateSaml2Options());


        }

        private static Saml2AuthenticationOptions CreateSaml2Options()
        
        {
            var spOptions = CreateSPOptions();
            var Saml2Options = new Saml2AuthenticationOptions(false)
            {
                SPOptions = spOptions
           
            };

            var idp = new IdentityProvider(new EntityId(ConfigurationManager.AppSettings["IDPEntityID"]), spOptions)
            {

                WantAuthnRequestsSigned = true,
                AllowUnsolicitedAuthnResponse = true,
                MetadataLocation = ConfigurationManager.AppSettings["IDPMetadataURL"],
                LoadMetadata = true,
                Binding = Saml2BindingType.HttpRedirect,
                //Logout Binding
                //SingleLogoutServiceBinding = Saml2BindingType.HttpPost,
                //SingleSignOnServiceUrl = new Uri("https://stubidp.sustainsys.com")
                SingleSignOnServiceUrl = new Uri(ConfigurationManager.AppSettings["IDPLoginURL"]),
                SingleLogoutServiceUrl = new Uri(ConfigurationManager.AppSettings["IDPLoginURL"]),
                //SingleLogoutServiceResponseUrl = new Uri("https://localhost:44303/saml2/logout"),
                DisableOutboundLogoutRequests = false
            };
            //idp.SigningKeys.AddConfiguredKey(
            //    new X509Certificate2(
            //        HostingEnvironment.MapPath(
            //            //"~/App_Data/stubidp.sustainsys.com.cer")));
            //            //IDP Signing Certificate
            //            "~/App_Data/adfssiging.cer")));

            Saml2Options.IdentityProviders.Add(idp);

            // It's enough to just create the federation and associate it
            // with the options. The federation will load the metadata and
            // update the options with any identity providers found.
            //new Federation("https://sts.azurehybrid.tk/FederationMetadata/2007-06/FederationMetadata.xml", true, Saml2Options);
            //Debug.WriteLine("stop here");

            return Saml2Options;
        }

        private static SPOptions CreateSPOptions()
        {
            
            var spOptions = new SPOptions
            {
                EntityId = new EntityId("https://localhost:44303/Saml2"),
                ReturnUrl = new Uri("https://localhost:44303/Account/ExternalLoginCallback"),
                //NameIdPolicy = new Saml2NameIdPolicy(true, NameIdFormat.EmailAddress),
                RequestedAuthnContext = new Saml2RequestedAuthnContext(new Uri("urn:federation:authentication:windows"), AuthnContextComparisonType.Exact),
                //RequestedAuthnContext = new Saml2RequestedAuthnContext(new RequestedAuthnContextElement()),
                

                //AuthenticateRequestSigningBehavior = SigningBehavior.Always,
               // DiscoveryServiceUrl = new Uri("https://localhost:44300/DiscoveryService"),
                //Organization = organization
            };
            spOptions.ServiceCertificates.Add(new X509Certificate2(
            //    //SP Signing Certificate
                AppDomain.CurrentDomain.SetupInformation.ApplicationBase + "/App_Data/Sustainsys.Saml2.Tests.pfx"));

            return spOptions;
        }

     
    }
}