ClaimsAuthenticationManager
===========================
When using federated authentication, the identity provider solely decides what claims to use to 
populate the incoming identity. If using multiple identity providers there is very high probability that 
they will present the same information in somewhat different ways. That's where the ``ClaimsAuthenticationManager`` 
fits in. It works as a translation filter that can modify or replace the incoming identity as soon as it has 
been constructed from the incoming authentication response.

You can implement a ``ClaimsAuthenticationManager`` by creating a class derived from the 
``System.Security.Claims.ClaimsAuthenticationManager`` class.

Then register it with a ``<claimsAuthenticationManager>`` element in the configuration if the configuration is 
loaded from the config file. If the configuration is done in code (typically for the OWIN middleware) 
the ClaimsAuthenticationManager should be registered in 
``Options.SPOptions.SystemIdentityModelIdentityConfiguration.ClaimsAuthenticationManager``.

Single Logout
--------------
If you are using Single Logout, you need to make sure that the claims containing the Saml2 logout information 
are present in the returned identity. The types of the claims are available in 
``Saml2ClaimTypes.SessionIndex`` and ``Saml2ClaimTypes.LogoutNameIdentifier``.