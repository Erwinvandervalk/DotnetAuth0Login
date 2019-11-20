using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace auth0login
{
    public class AutoFollowRedirectHandler : DelegatingHandler
    {
        public AutoFollowRedirectHandler(HttpMessageHandler innerHandler) : base(innerHandler)
        {
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            HttpResponseMessage result;
            var previousUri = request.RequestUri;
            for (var i = 0; i < 20; i++)
            {
                result = await base.SendAsync(request, cancellationToken);
                if (result.StatusCode == HttpStatusCode.Found)
                {
                    var newUri = result.Headers.Location;
                    if (!newUri.IsAbsoluteUri) newUri = new Uri(previousUri, newUri);
                    var headers = request.Headers;
                    request = new HttpRequestMessage(HttpMethod.Get, newUri);
                    foreach (var header in headers) request.Headers.Add(header.Key, header.Value);
                    previousUri = request.RequestUri;
                    continue;
                }

                return result;
            }

            throw new InvalidOperationException("Keeps redirecting forever");
        }
    }
}