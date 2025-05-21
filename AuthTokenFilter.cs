using TokenValidation.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using TokenValidation.Constant;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Cryptography;
using System.Text;
using TokenValidation.Utilities;

namespace TokenValidation.Filters
{
    public class AuthenticationFilterAttribute : Attribute, IAuthorizationFilter
    {
        private IOptions<AuthSettings> settings;
       
        public AuthenticationFilterAttribute(IOptions<AuthSettings> settings)
        {
            this.settings = settings;
        }
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            ValidateTokenAsync(context);
        }
        private async Task ValidateTokenAsync(AuthorizationFilterContext context)
        {
            string token; string appUrl = "";
            if (!TryRetrieveToken(context.HttpContext.Request, out token))
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            try
            {
                List<Claim> audience = ((JwtSecurityToken)new JwtSecurityTokenHandler().ReadToken(token)).Claims.ToList();
                var issuer = audience.FirstOrDefault(x => x.Type == CloudConstant.Iss).Value;
                var exp = audience.FirstOrDefault(x => x.Type == CloudConstant.Exp)?.Value;
                if (!string.IsNullOrEmpty(this.settings.Value.AppUrl))
                {
                    appUrl = CryptoUtil.DecryptString(audience.FirstOrDefault(x => x.Type == CloudConstant.AppUrl)?.Value);
                }
                string stsDiscoveryEndpoint = audience.FirstOrDefault(x => x.Type == CloudConstant.idp)?.Value == CloudConstant.SAMLIdp? CloudConstant.stsDiscoveryEndpointCustomUserpolicy : CloudConstant.stsDiscoveryEndpointUserpolicy;

                if (VerifyAWSToken(token, CloudConstant.secret))
                {
                    bool isVerifiedPayload = await VerifyPayload(token, issuer, exp, appUrl).ConfigureAwait(false);
                    if (isVerifiedPayload)
                    {
                        var identity = new ClaimsIdentity();
                        identity.AddClaims(audience);
                        var principal = new ClaimsPrincipal(identity);
                        context.HttpContext.User = principal;
                        return;
                    }
                    else
                    {
                        context.Result = new UnauthorizedResult();
                        return;
                    }
                }
                else
                {
                    context.Result = new UnauthorizedResult();
                    return;
                }
            }
            catch (SecurityTokenValidationException e)
            {
                context.Result = new UnauthorizedResult();
                return;
            }
            catch (Exception ex)
            {
                context.Result = new UnauthorizedResult();
                return;
            }

        }

        private async Task<bool> VerifyPayload(string token, string issuer, string exp, string appUrl)
        {
            bool validToken = false;
            if (exp != null)
            {
                var expDate = UnixTimeStampToDateTime(double.Parse(exp, CultureInfo.InvariantCulture));
                if (settings != null && settings.Value != null && !string.IsNullOrEmpty(settings.Value.AWSIss))
                {
                    if (!string.IsNullOrEmpty(settings.Value.AppUrl))
                        validToken = (issuer.Equals(settings.Value.AWSIss) || issuer.Equals(CloudConstant.AWSNewIss)) && (DateTime.UtcNow < expDate) && (settings.Value.AppUrl == appUrl);
                    else
                        validToken = (issuer.Equals(settings.Value.AWSIss) || issuer.Equals(CloudConstant.AWSNewIss)) && (DateTime.UtcNow < expDate);
                }
                else
                {
                    if (!string.IsNullOrEmpty(settings.Value.AppUrl))
                        validToken = (issuer.Equals(CloudConstant.AWSNewIss) || issuer.Equals(CloudConstant.AWSIss)) && (DateTime.UtcNow < expDate) && (settings.Value.AppUrl == appUrl);
                    else
                        validToken = (issuer.Equals(CloudConstant.AWSNewIss) || issuer.Equals(CloudConstant.AWSIss)) && (DateTime.UtcNow < expDate);
                }
            }

            return validToken;
        }

        private async Task<bool> VerifyAzureToken(string token, string stsDiscoveryEndpoint)
        {
            try
            {
                var configManager = new ConfigurationManager<OpenIdConnectConfiguration>(stsDiscoveryEndpoint, new OpenIdConnectConfigurationRetriever()); //1. need the 'new OpenIdConnect...'
                OpenIdConnectConfiguration config = configManager.GetConfigurationAsync().Result;
                TokenValidationParameters validationParameters = new TokenValidationParameters
                {
                    //decode the JWT to see what these values should be
                    ValidAudience = CloudConstant.validAudience,  // Replaced values by XXXX
                    IssuerSigningKeys = config.SigningKeys, //2. .NET Core equivalent is "IssuerSigningKeys" and "SigningKeys"
                    ValidateIssuer = false,
                    ValidIssuer = CloudConstant.validIssuer,
                    ValidateAudience = true,
                    ValidateIssuerSigningKey = false,
                    RequireExpirationTime = false,
                    ValidateLifetime = false,
                };
                JwtSecurityTokenHandler tokendHandler = new JwtSecurityTokenHandler();
                SecurityToken jwt;
                tokendHandler.ValidateToken(token, validationParameters, out jwt);
                return true;
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        private static bool VerifyAWSToken(string token, string secret)
        {
            string[] parts = token.Split(".".ToCharArray());
            if (parts != null && parts.Count() == 3)
            {
                var header = parts[0];
                var payload = parts[1];
                var signature = parts[2];//Base64UrlEncoded signature from the token

                byte[] bytesToSign = getBytes(string.Join(".", header, payload));

                byte[] secretbyte = getBytes(secret);

                var alg = new HMACSHA256(secretbyte);
                var hash = alg.ComputeHash(bytesToSign);

                var computedSignature = Base64UrlEncode(hash);
                if (computedSignature == signature)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }

        private static byte[] getBytes(string value)
        {
            return Encoding.UTF8.GetBytes(value);
        }

        // from JWT spec
        private static string Base64UrlEncode(byte[] input)
        {
            var output = Convert.ToBase64String(input);
            output = output.Split('=')[0]; // Remove any trailing '='s
            output = output.Replace('+', '-'); // 62nd char of encoding
            output = output.Replace('/', '_'); // 63rd char of encoding
            return output;
        }

        private bool TryRetrieveToken(HttpRequest request, out string token)
        {
            token = null;
            Microsoft.Extensions.Primitives.StringValues authzHeaders;
            if (!request.Headers.TryGetValue(CloudConstant.authorization, out authzHeaders) || authzHeaders.Count() > 1)
            {
                return false;
            }
            var bearerToken = authzHeaders.ElementAt(0);
            token = bearerToken.StartsWith(CloudConstant.bearer) ? bearerToken.Substring(7) : bearerToken;
            return true;
        }

        public static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            dtDateTime = dtDateTime.AddSeconds(unixTimeStamp);//.ToLocalTime();
            return dtDateTime;
        }

    }
}
