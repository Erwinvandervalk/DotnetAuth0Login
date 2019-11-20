using System;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace auth0login
{
    public class GetAccessTokenTests
    {
        private readonly ITestOutputHelper _output;

        private LoginFixture _fixture;

        public GetAccessTokenTests(ITestOutputHelper output)
        {
            _output = output;
            _fixture = new LoginFixture(output.WriteLine);
        }

        [Fact]
        public async Task Get_access_token()
        {
            var token = await _fixture.Login(new LoginSettings()
            {
                Authority = new Uri("<<url to your auth0 tenant>>"),

                // Without an audience, you'll get a token that cannot access anything
                // and is only valid to request userinfo. 
                Audience = "<<audience here>>",

                Auth0Tenant = "<<tenantid here>>",


                ClientId = "<client id here>>",

                // Haven't been able to get it to work without a client secret
                ClientSecret = "<<client secret here>>",

                // The redirecturi that you have configured for your application
                // Note, this URL does not have to be valid, as long as it's registered with auth0,
                // as requests to it will get intercepted
                RedirectUri = new Uri("<<redirecturi here>"),

                // If you use a custom auth0 connection to store your user, put it here
                Connection = "Username-Password-Authentication",
                Scopes = new[] { "openid", "profile", "email", "role" },


                UserName = "<<username goes here>>",
                Password = "<<password goes here>>"
            });

            _output.WriteLine(token.AccessToken);

            Assert.NotEmpty(token.AccessToken);

        }
    }
}
