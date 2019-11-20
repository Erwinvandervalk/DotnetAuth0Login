using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using HtmlAgilityPack;
using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.WebUtilities;
using Newtonsoft.Json;

namespace auth0login
{
    /// <summary>
    /// This class does all the heavy lifting to get an access token. 
    /// </summary>
    public class LoginFixture
    {
        private readonly Action<string> _log;

        public LoginFixture(Action<string> log)
        {
            _log = log;
        }

        public async Task<TokenResponse> Login(LoginSettings loginSettings)
        {
            _log($"Logging in user {loginSettings.UserName} to {loginSettings.Authority}");

            var httpClient = new HttpClient(

                // We're following the auto-redirects explicitly. 
                // The http client handler can also follow redirects, but then we can't intercept the request to the return url. 
                new AutoFollowRedirectHandler(

                    // Handler that intercepts the requests to the return url, so the return url
                    // doesn't actually have to be valid (just registered with auth0)
                    new InterceptRedirectBackHandler(
                        loginSettings.RedirectUri.Host, 

                        // Actual http handler that invokes auth0
                        new HttpClientHandler()
                    )
                )
            );

            // Retrieve the discovery document. In theory we could hard-code the url's,
            // but this follows the standards better. 
            var disco = await httpClient.GetDiscoveryDocumentAsync(new DiscoveryDocumentRequest()
            {
                Address = loginSettings.Authority.ToString(),
            });

            if (disco.IsError)
            {
                // Verify that the authority is available"
                throw new InvalidOperationException($"Failed to access authority discovery document: {disco.HttpStatusCode}: {disco.Error}");
            }

            // Step 1: Create and go to authorize url
            var request = new RequestUrl(disco.AuthorizeEndpoint);
            var cryptoHelper = new CryptoHelper();
            var pkce = cryptoHelper.CreatePkceData();
            var clientId = loginSettings.ClientId;
            
            var authorizeUrl = request.CreateAuthorizeUrl(
                clientId,
                OidcConstants.ResponseTypes.Code,
                responseMode: OidcConstants.ResponseModes.Query,
                redirectUri: loginSettings.RedirectUri.ToString(),
                codeChallenge: pkce.CodeChallenge,
                codeChallengeMethod: OidcConstants.CodeChallengeMethods.Sha256,
                scope: string.Join(" ", loginSettings.Scopes),
                extra: new
                {
                    audience = loginSettings.Audience
                });
            _log("  - Login Step 1: Create and go to authorize url: " + authorizeUrl);
            var response = await httpClient.GetAsync(authorizeUrl);

            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new InvalidOperationException($"Invalid response code in Step 1. StatusCode: {response.StatusCode} authorize url: {authorizeUrl}.");
            }

            // Get the request querystring to extract the state property
            var query = QueryHelpers.ParseQuery(response.RequestMessage.RequestUri.Query);
            var state = query["state"].ToString();


            // The spec doesn't say where to post the login details to
            // but it's at /usernamepassword/login
            var loginPage = loginSettings.Authority.GetLeftPart(System.UriPartial.Authority) + "/usernamepassword/login";
            _log("  - Login Step 2: Post login details to login page: " + loginPage);
            // Create a json post to that url with the riight properties
            var requestMessage = new HttpRequestMessage(HttpMethod.Post, loginPage)
            {
                Content = new StringContent(JsonConvert.SerializeObject(new
                {
                    client_id = clientId,
                    redirect_uri = loginSettings.RedirectUri.ToString(),
                    tenant = loginSettings.Auth0Tenant,
                    connection = loginSettings.Connection,
                    username = loginSettings.UserName,
                    state = state,
                    password = loginSettings.Password,
                }), Encoding.UTF8, "application/json")
            };

            response = await httpClient.SendAsync(requestMessage);
            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new InvalidOperationException($"Invalid response code in Step 2. StatusCode: {response.StatusCode} login page: {loginPage}. {await response.Content.ReadAsStringAsync()}");
            }

            
            var doc = new HtmlDocument();
            doc.LoadHtml(await response.Content.ReadAsStringAsync());

            var form = doc.DocumentNode.FirstChild;
            var action = form.Attributes["action"].Value;
            _log($"  - Login Step 3: The response contains a form. Post it to: {action}");
            var inputElements = form
                .SelectNodes("input")
                .Select(x =>
                    new KeyValuePair<string, string>
                    (
                        x.Attributes["name"].Value,
                        HttpUtility.HtmlDecode(x.Attributes["value"].Value)
                    )
                );

            requestMessage = new HttpRequestMessage(HttpMethod.Post, action)
            {
                Content = new FormUrlEncodedContent(inputElements)
            };

            response = await httpClient.SendAsync(requestMessage);

            if (response.StatusCode != HttpStatusCode.OK)
            {
                throw new InvalidOperationException($"Invalid response code in Step 3. StatusCode: {response.StatusCode} action: {action}. {await response.Content.ReadAsStringAsync()}");
            }


            var location = response.RequestMessage.RequestUri;
            _log($"  - Login Step 4: We are now redirected at the redirect-page. Get the authorization code from url: {location}");
            query = QueryHelpers.ParseQuery(location.Query);
            if (!query.TryGetValue("code", out var code))
                throw new InvalidOperationException("Failed step 4. Could not find code in url: " + location);

            _log($"  - Login Step 5: Swap authorization code for an access token. ");
            var tokenResponse = await httpClient.RequestAuthorizationCodeTokenAsync(new AuthorizationCodeTokenRequest
            {
                Address = disco.TokenEndpoint,

                ClientId = clientId,
                ClientCredentialStyle = ClientCredentialStyle.AuthorizationHeader,
                ClientSecret = loginSettings.ClientSecret,
                Code = code,
                RedirectUri = loginSettings.RedirectUri.ToString(),
                CodeVerifier = pkce.CodeVerifier,
                Parameters = new Dictionary<string, string>()
            });
            if (tokenResponse.HttpStatusCode != HttpStatusCode.OK)
            {
                throw new InvalidOperationException($"Failed step 5. statuscode not ok: {tokenResponse.HttpStatusCode} {tokenResponse.ErrorDescription} {tokenResponse.Error}");
            }

            return tokenResponse;
        }

    }
}