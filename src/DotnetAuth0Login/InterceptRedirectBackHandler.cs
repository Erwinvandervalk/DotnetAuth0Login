using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace auth0login
{
    public class InterceptRedirectBackHandler : DelegatingHandler
    {
        private readonly string _host;

        public InterceptRedirectBackHandler(string host, HttpMessageHandler innerHandler) : base(innerHandler)
        {
            _host = host;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (string.Equals(request.RequestUri.Host, _host, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { RequestMessage = request });
            }

            return base.SendAsync(request, cancellationToken);
        }
    }
}