# DotnetAuth0Login

This repo demonstrates how you can log in to auth0 using username + password using Authorization Code flow.

As part of our automated smoke tests, we want to be able to simulate a user logging in. This code does that. 

It took me a while to figure out how to do this, so in this repo i'm capturing my learnings. 

## Usage:

This code requests a token. 

``` c#

            var token = await _fixture.Login(new LoginSettings()
            {
                Authority = new Uri("<<url to your auth0 tenant>>"),

                // Without an audience, you'll get a token that cannot access anything
                // and is only valid to request userinfo. 
                Audience = "<<audience here>>",

                Auth0Tenant = "<<tenantid here>>",


                ClientId = "<client id here>>",

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

```


