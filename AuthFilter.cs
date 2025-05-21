using System;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using TokenValidationFramework.Helper;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Http.Filters;
using System.Configuration;
using System.Globalization;
using Microsoft.IdentityModel.Tokens;

namespace TokenValidationFramework
{
    public class AuthenticationFilterAttribute : Attribute, IAuthenticationFilter
    {
        /// <summary>
        /// Defines the b2cLogin.
        /// </summary>
        private static readonly string AWSIss = ConfigurationManager.AppSettings["AWSIss"];

        /// <summary>
        /// Defines the clientId.
        /// </summary>
        private static readonly string AzureIss = ConfigurationManager.AppSettings["AzureIss"];
        /// <summary>
        /// Defines the Exp.
        /// </summary>
        private static readonly string Exp = "exp";
        /// <summary>
        /// Defines the Iss.
        /// </summary>
        private static readonly string Iss = "iss";

        /// <summary>
        /// The AuthenticateAsync.
        /// </summary>
        /// <param name="context">.</param>
        /// <param name="cancellationToken">.</param>
        /// <returns>.</returns>
        public async Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            ValidateToken(context);
        }

        private void ValidateToken(HttpAuthenticationContext context)
        {
            string token;
            //determine whether a jwt exists or not
            if (!TryRetrieveToken(context.Request, out token))
            {
                context.ErrorResult = new AuthenticationFailureResult("Unauthorized access", context.Request);
                return;
            }

            try
            {
                List<Claim> audience = ((JwtSecurityToken)new JwtSecurityTokenHandler().ReadToken(token)).Claims.ToList();
                var issuer = audience.FirstOrDefault(x => x.Type == Iss).Value;
                var exp = audience.FirstOrDefault(x => x.Type == Exp)?.Value;
                bool validToken;
                if (exp != null)
                {
                    var expDate = UnixTimeStampToDateTime(double.Parse(exp, CultureInfo.InvariantCulture));
                    if (!string.IsNullOrEmpty(AWSIss))
                    {
                        validToken = (issuer.Contains(AWSIss) || issuer.Contains(CloudConstant.AWSNewIss)) && (DateTime.UtcNow < expDate);
                    }
                    else
                    {
                        validToken = (issuer.Contains(CloudConstant.AWSIss) || issuer.Contains(CloudConstant.AWSNewIss)) && (DateTime.UtcNow < expDate);
                    }
                    if (validToken) return;
                }

                context.ErrorResult = new AuthenticationFailureResult("Unauthorized access", context.Request);
            }
            catch (SecurityTokenValidationException e)
            {
                context.ErrorResult = new AuthenticationFailureResult("Unauthorized access", context.Request);
                return;
            }
            catch (Exception ex)
            {
                //Logger.Logger.Error(message: "Error occurred while validating bearer token. Message: " + ex.Message + "; StackTrace: " + ex.StackTrace);
                context.ErrorResult =
                    new AuthenticationFailureResult("Error occurred while validating bearer token", context.Request);
                return;
            }
        }

        /// <summary>
        /// The ChallengeAsync.
        /// </summary>
        /// <param name="context">.</param>
        /// <param name="cancellationToken">.</param>
        /// <returns>.</returns>
        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            //Need cloud implementation
            return Task.FromResult(0);
        }

        /// <summary>
        /// The TryRetrieveToken.
        /// </summary>
        /// <param name="request">The request<see cref="HttpRequestMessage"/>.</param>
        /// <param name="token">The token<see cref="string"/>.</param>
        /// <returns>The <see cref="bool"/>.</returns>
        private static bool TryRetrieveToken(HttpRequestMessage request, out string token)
        {
            token = null;
            IEnumerable<string> authzHeaders;
            if (!request.Headers.TryGetValues("Authorization", out authzHeaders) || authzHeaders.Count() > 1)
            {
                return false;
            }
            var bearerToken = authzHeaders.ElementAt(0);
            token = bearerToken.StartsWith("Bearer ") ? bearerToken.Substring(7) : bearerToken;
            return true;
        }

        public static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            dtDateTime = dtDateTime.AddSeconds(unixTimeStamp);//.ToLocalTime();
            return dtDateTime;
        }

        public bool AllowMultiple
        {
            get
            {
                return true;
            }
        }

        /// <summary>
        /// Defines the <see cref="AuthenticationFailureResult" />.
        /// </summary>
        public class AuthenticationFailureResult : IHttpActionResult
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="AuthenticationFailureResult"/> class.
            /// </summary>
            /// <param name="reasonPhrase">.</param>
            /// <param name="request">.</param>
            public AuthenticationFailureResult(string reasonPhrase, HttpRequestMessage request)
            {
                ReasonPhrase = reasonPhrase;
                Request = request;
            }


            /// <summary>
            /// Gets the ReasonPhrase.
            /// </summary>
            public string ReasonPhrase { get; private set; }

            /// <summary>
            /// Gets the Request.
            /// </summary>
            public HttpRequestMessage Request { get; private set; }

            /// <summary>
            /// The ExecuteAsync.
            /// </summary>
            /// <param name="cancellationToken">.</param>
            /// <returns>.</returns>
            public Task<HttpResponseMessage> ExecuteAsync(CancellationToken cancellationToken)
            {
                return Task.FromResult(Execute());
            }

            /// <summary>
            /// The Execute.
            /// </summary>
            /// <returns>The <see cref="HttpResponseMessage"/>.</returns>
            private HttpResponseMessage Execute()
            {
                HttpResponseMessage response = new HttpResponseMessage(HttpStatusCode.Unauthorized);
                response.RequestMessage = Request;
                response.ReasonPhrase = ReasonPhrase;
                return response;
            }

        }

    }
}