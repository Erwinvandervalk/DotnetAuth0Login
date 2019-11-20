using System;
using System.Collections.Generic;

namespace auth0login
{
    public class LoginSettings
    {
        public Uri RedirectUri { get; set; }
        public Uri Authority { get; set; }
        public string Audience { get; set; }

        public ICollection<string> Scopes { get; set; }
        
        public string UserName { get; set; }
        public string Password { get; set; }
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string Auth0Tenant { get; set; }
        public string Connection { get; set; }
    }
}