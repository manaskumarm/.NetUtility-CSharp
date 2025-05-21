using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Ccs.Uno.Common.Utils;
using AutoMapper;
using Ccs.Uno.UserManagement.Repository;
using Ccs.Uno.UserManagement.Service.Helper;
using Ccs.Uno.UserManagement.Service.Model;
using Microsoft.Graph;
using Ccs.Uno.UserManagement.Repository.Context;
using Microsoft.Azure.ActiveDirectory.GraphClient;
using Microsoft.Extensions.Configuration;
using Ccs.Uno.UserManagement.Service.Interfaces;
using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using Ccs.Uno.Common.Utils.Cloud;
using Ccs.Uno.UserManagement.Service.Biz;
using DocumentFormat.OpenXml.Spreadsheet;

#pragma warning disable CA2234 // Pass system uri objects instead of strings

namespace Service.Utility
{
    public class ActiveDirectoryService : IActiveDirectoryService
    {
        private string accessToken = string.Empty;
        private string b2cAccessToken = string.Empty;
        private readonly ADParameters allAdParameters;
        private readonly ActiveDirectoryParameterModel adParameters;
        private readonly ActiveDirectoryParameterModel carrierAdParameters;
        private readonly ActiveDirectoryParameterModel cognitoUserLogin;

        private readonly IMapper mapper;
        private readonly B2CGraphClient client;
        private static GraphServiceClient graphClient = null;
        private readonly IConfigurationRoot configuration;
        private readonly IAwsManagerReadKey awsManagerReadKey;

        public IApplication app { get; private set; }

        public ActiveDirectoryService(IAwsManagerReadKey awsManagerReadKey)
        {
            var Configuration = new ConfigurationBuilder().SetBasePath(System.IO.Directory.GetCurrentDirectory()).AddJsonFile("appsettings.json", optional: true, reloadOnChange: true).Build();
            var CarrierAD = new ActiveDirectoryParameterModel()
            {
                Instance = Configuration["ApiSettings:ADParameters:CarrierAD:Instance"],
                Domain = Configuration["ApiSettings:ADParameters:CarrierAD:Domain"],
                TenantId = Guid.Parse(awsManagerReadKey.AppConfigKeys["TenantId"]),//(Configuration["ApiSettings:ADParameters:CarrierAD:TenantId"]),
                ClientId = Guid.Parse(awsManagerReadKey.AppConfigKeys["ClientId"]),//(Configuration["ApiSettings:ADParameters:CarrierAD:ClientId"]),
                ClientSecretKey = awsManagerReadKey.AppConfigKeys["ClientSecretKey"], //Configuration["ApiSettings:ADParameters:CarrierAD:ClientSecretKey"],
                GraphResource = Configuration["ApiSettings:ADParameters:CarrierAD:GraphResource"]
            };
            var UnoB2C = new ActiveDirectoryParameterModel()
            {
                InstanceB2C = Configuration["ApiSettings:ADParameters:UnoB2C:InstanceB2C"],
                Domain = Configuration["ApiSettings:ADParameters:UnoB2C:Domain"],
                TenantId = Guid.Parse(Configuration["ApiSettings:ADParameters:UnoB2C:TenantId"]),
                ClientId = Guid.Parse(Configuration["ApiSettings:ADParameters:UnoB2C:ClientId"]),
                ClientSecretKey = Configuration["ApiSettings:ADParameters:UnoB2C:ClientSecretKey"],
                GraphResource = Configuration["ApiSettings:ADParameters:UnoB2C:GraphResource"],
                GraphScopes = Configuration["ApiSettings:ADParameters:UnoB2C:GraphScopes"],
                B2CClientId = Configuration["ApiSettings:ADParameters:UnoB2C:B2CClientId"],
                B2CNativeClient = Configuration["ApiSettings:ADParameters:UnoB2C:B2CNativeClient"],
                ROPC = Configuration["ApiSettings:ADParameters:UnoB2C:ROPC"],
                B2CAuthUrl = Configuration["ApiSettings:ADParameters:UnoB2C:B2CAuthUrl"],

            };
            var CognitoUserLogin = new ActiveDirectoryParameterModel()
            {
                UserPoolId = awsManagerReadKey.AppConfigKeys["PoolId"],//Configuration["AWSCognito:PoolId"],
                AwsClientId = awsManagerReadKey.AppConfigKeys["ClientId_Cognito"],//Configuration["AWSCognito:CientId"],
                AwsSecret = awsManagerReadKey.AppConfigKeys["Secret"]//Configuration["AWSCognito:Secret"]
            };
            this.adParameters = UnoB2C;
            carrierAdParameters = CarrierAD;
            cognitoUserLogin = CognitoUserLogin;

            client = new B2CGraphClient(UnoB2C);
            var config = new MapperConfiguration(cfg =>
            {
                cfg.CreateMap<VUserDetails, UserDetailsModel>();
            });

            mapper = config.CreateMapper();
            this.awsManagerReadKey = awsManagerReadKey;
        }

        #region MicrosftGraphAPI
        private async Task<bool> ValidateAccessToken()
        {
            if (String.IsNullOrWhiteSpace(accessToken))
                return true;

            try
            {
                string instance = adParameters.InstanceB2C;
                string authority = String.Format(CultureInfo.InvariantCulture,
                    instance, adParameters.Domain);

                AuthenticationContext authContext = new AuthenticationContext(authority);
                ClientCredential clientCredential = new ClientCredential(adParameters.ClientId.ToString(),
                    adParameters.ClientSecretKey);

                AuthenticationResult result = await authContext.AcquireTokenAsync(adParameters.GraphResource, clientCredential).ConfigureAwait(false);

                accessToken = result.AccessToken;
                if (string.IsNullOrWhiteSpace(accessToken))
                    throw new UnoSecurityException(SecurityErrorCode.InvalidToken, UnoErrorStatus.Unauthenticated,
                        SecurityErrorCode.InvalidToken.GetErrorReferenceDescription());

                return true;
            }
            catch (UnoSecurityException)
            {
                throw;
            }
            catch (NullReferenceException)
            {
                throw new UnoSecurityException(SecurityErrorCode.NullReferenceException, UnoErrorStatus.Internal, "NullReferenceException occured in ValidateAccessToken");
            }
            catch (ArgumentNullException)
            {
                throw new UnoSecurityException(SecurityErrorCode.NullReferenceException, UnoErrorStatus.Internal, "NullReferenceException occured in ValidateAccessToken");
            }
            catch (AdalServiceException e)
            {
                throw new UnoSecurityException(SecurityErrorCode.AdalServiceException, UnoErrorStatus.Internal,
                    string.Format(CultureInfo.InvariantCulture, "Original Code and Message= {0}: {1}", e.ErrorCode, e.ServiceErrorCodes));
            }
            catch (AdalException e)
            {
                throw new UnoSecurityException(SecurityErrorCode.AdalException, UnoErrorStatus.Internal,
                    string.Format(CultureInfo.InvariantCulture, "Original Code and Message= {0}: {1}", e.ErrorCode, e.Message));
            }
            catch (Exception e)
            {
                throw new UnoBaseException(UnoErrorStatus.Internal, e.Message, "0000");
            }
        }

        private HttpClient GetHttpClient()
        {
            var clientConnection = new HttpClient();
            clientConnection.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            return clientConnection;
        }

        public async Task<AuthUserModel> GetUser(string userName)
        {
            await ValidateAccessToken().ConfigureAwait(false);

            try
            {
                using (var clientConnection = GetHttpClient())
                {
                    AuthUserModel user;

                    using (var response = clientConnection.GetAsync(GraphUrlHelper.GraphUser + userName).Result)
                    {
                        try
                        {
                            response.EnsureSuccessStatusCode();
                            user = response.Content.ReadAsAsync<AuthUserModel>().Result;
                            return user;
                        }
                        catch (HttpRequestException e)
                        {
                            if (response.StatusCode == HttpStatusCode.NotFound) // 404
                            {
                                throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                    SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                            }
                            else
                            {
                                throw new UnoHttpException((int)response.StatusCode,
                                    e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                            }
                        }
                    }
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        public async Task<GroupUserListModel> GetUsersInGroup(string groupName)
        {
            await ValidateAccessToken().ConfigureAwait(false);

            string groupId = await GetGroupId(groupName).ConfigureAwait(false);

            var getMemberListInGroupUrl = new Uri(String.Format(CultureInfo.InvariantCulture, GraphUrlHelper.GraphGroupUserLists, groupId));

            try
            {
                using (var clientConnection = GetHttpClient())
                {

                    using (var response = clientConnection.GetAsync(getMemberListInGroupUrl).Result)
                    {
                        try
                        {
                            response.EnsureSuccessStatusCode();
                            var usersDetials = await response.Content.ReadAsAsync<GroupUserListModel>().ConfigureAwait(false);
                            return usersDetials;
                        }
                        catch (HttpRequestException e)
                        {
                            if (response.StatusCode == HttpStatusCode.NotFound) // 404
                            {
                                throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                    SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                            }
                            else
                            {
                                throw new UnoHttpException((int)response.StatusCode,
                                    e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                            }
                        }
                    }
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }

        }

        public async Task<HttpStatusCode> CreateUser(UserSignUpModel signupuserdetails)
        {
            await ValidateAccessToken().ConfigureAwait(false);
            UserSignUpModel user;

            try
            {
                using (var clientConnection = GetHttpClient())
                {
                    using (var stream = new MemoryStream())
                    {
                        using (var writer = new StreamWriter(stream))
                        {
                            var payload = new
                            {
                                accountEnabled = true,
                                displayName = signupuserdetails.FirstName,
                                mailNickname = signupuserdetails.FirstName,
                                userPrincipalName = $"{signupuserdetails.UserName}@{adParameters.Domain}",
                                passwordProfile = new
                                {
                                    forceChangePasswordNextSignIn = true,
                                    password = signupuserdetails.Password
                                }
                            };

                            var userdetails = JsonConvert.SerializeObject(payload);
                            writer.Write(userdetails);
                            writer.Flush();
                            stream.Flush();
                            stream.Position = 0;

                            using (var content = new StreamContent(stream))
                            {
                                content.Headers.Add("Content-Type", "application/json");

                                using (var response = clientConnection.PostAsync(GraphUrlHelper.GraphUser, content).Result)
                                {
                                    try
                                    {
                                        response.EnsureSuccessStatusCode();

                                        user = response.Content.ReadAsAsync<UserSignUpModel>().Result;

                                        signupuserdetails.Id = user.Id;

                                        var updatedUserDetailsRequestStatus = await UpdateUser(signupuserdetails).ConfigureAwait(false);

                                        if (updatedUserDetailsRequestStatus == HttpStatusCode.NoContent)
                                        {
                                            return response.StatusCode;
                                        }
                                        else
                                        {
                                            throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                                SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                                        }
                                    }
                                    catch (HttpRequestException e)
                                    {
                                        if (response.StatusCode == HttpStatusCode.NotFound) // 404
                                        {
                                            throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                                SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                                        }
                                        else
                                        {
                                            throw new UnoHttpException((int)response.StatusCode,
                                                e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }

        }

        public async Task<HttpStatusCode> DeleteUser(string UserId)
        {
            await ValidateAccessToken().ConfigureAwait(false);

            var deleteUserUrl = new Uri(String.Format(CultureInfo.InvariantCulture, GraphUrlHelper.GraphDeleteUser, UserId));

            try
            {
                using (var clientConnection = GetHttpClient())
                {
                    using (var response = await clientConnection.DeleteAsync(deleteUserUrl).ConfigureAwait(false))
                    {
                        try
                        {
                            response.EnsureSuccessStatusCode();
                            return response.StatusCode;
                        }
                        catch (HttpRequestException e)
                        {
                            if (response.StatusCode == HttpStatusCode.NotFound) // 404
                            {
                                throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                    SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                            }
                            else
                            {
                                throw new UnoHttpException((int)response.StatusCode,
                                    e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                            }
                        }
                    }
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        public async Task<HttpStatusCode> UpdateUser(UserSignUpModel userdetails)
        {
            await ValidateAccessToken().ConfigureAwait(false);
            try
            {
                var updateUserDetailsUrl = string.Concat(GraphUrlHelper.GraphUser, userdetails.Id);
                using (var clientConnection = GetHttpClient())
                {
                    using (var stream = new MemoryStream())
                    {
                        using (var writer = new StreamWriter(stream))
                        {
                            var payload = new
                            {
                                givenName = userdetails.FirstName,
                                surname = userdetails.SurName,
                                country = userdetails.Country,
                                mobilePhone = userdetails.MobileNo,
                                state = userdetails.State,
                                streetAddress = userdetails.Address,
                                city = userdetails.City,
                                postalCode = userdetails.PostalCode
                            };

                            var userupdatedetails = JsonConvert.SerializeObject(payload, Newtonsoft.Json.Formatting.None,
                                new JsonSerializerSettings
                                {
                                    NullValueHandling = NullValueHandling.Ignore
                                });

                            writer.Write(userupdatedetails);
                            writer.Flush();
                            stream.Flush();
                            stream.Position = 0;

                            using (var content = new StreamContent(stream))
                            {
                                content.Headers.Add("Content-Type", "application/json");

                                using (var response = clientConnection.PatchAsync(updateUserDetailsUrl, content).Result)
                                {
                                    try
                                    {
                                        response.EnsureSuccessStatusCode();
                                        return response.StatusCode;
                                    }
                                    catch (HttpRequestException e)
                                    {
                                        if (response.StatusCode == HttpStatusCode.NotFound) // 404
                                        {
                                            throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                                SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                                        }
                                        else
                                        {
                                            throw new UnoHttpException((int)response.StatusCode,
                                                e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        public async Task<HttpStatusCode> SendInvitation(B2BUserInvitationModel invitation)
        {
            await ValidateAccessToken().ConfigureAwait(false);

            try
            {
                using (var clientConnection = GetHttpClient())
                {
                    B2BUserInvitationModel postinvitation = new B2BUserInvitationModel
                    {
                        InvitedUserDisplayName = invitation.InvitedUserDisplayName,
                        InvitedUserEmailAddress = invitation.InvitedUserEmailAddress,
                        InviteRedirectUrl = invitation.InviteRedirectUrl,
                        SendInvitationMessage = true
                    };

                    HttpContent content = new StringContent(JsonConvert.SerializeObject(postinvitation));

                    clientConnection.DefaultRequestHeaders.Add("ContentType", "application/json");

                    using (var response = clientConnection.PostAsync(GraphUrlHelper.GraphInviteEndPoint, content).Result)
                    {
                        try
                        {
                            return response.StatusCode;
                        }
                        catch (HttpRequestException e)
                        {
                            if (response.StatusCode == HttpStatusCode.NotFound) // 404
                            {
                                throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                    SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                            }
                            else
                            {
                                throw new UnoHttpException((int)response.StatusCode,
                                    e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                            }
                        }
                    }
                }
            }
            catch (HttpRequestException e)
            {
                throw new UnoHttpException((int)UnoErrorStatus.Internal, e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        public async Task<AuthUserModel> AuthenticateUser(string userName, string password)
        {
            await ValidateAccessToken().ConfigureAwait(false);
            string authUrl = String.Format(CultureInfo.InvariantCulture, adParameters.B2CAuthUrl, adParameters.TenantId);
            var oauthEndpoint = new Uri(authUrl);

            using (var clientConnection = GetHttpClient())
            {
                clientConnection.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);

                var response = await clientConnection.PostAsync(oauthEndpoint, new FormUrlEncodedContent(new[]
                {
                            new KeyValuePair<string, string>("resource", GraphUrlHelper.GraphResourceId),
                            new KeyValuePair<string, string>("client_id",  adParameters.ClientId.ToString()),
                            new KeyValuePair<string, string>("client_secret", adParameters.ClientSecretKey),
                            new KeyValuePair<string, string>("grant_type", "password"),
                            new KeyValuePair<string, string>("username", userName),
                            new KeyValuePair<string, string>("password", password),
                            new KeyValuePair<string, string>("scope", "openid"),
                        })).ConfigureAwait(false);

                try
                {
                    response.EnsureSuccessStatusCode();
                    var userDetails = await GetUser(userName).ConfigureAwait(false);
                    var authdetails = await response.Content.ReadAsAsync<OAuthTokenModel>().ConfigureAwait(false);
                    var payload = new AuthUserModel
                    {

                        Username = userDetails.Username,
                        Id = userDetails.Id,
                        RoleName = userDetails.RoleName,
                        GivenName = userDetails.GivenName,
                        Surname = userDetails.Surname,
                        MobilePhone = userDetails.MobilePhone,
                        OfficeLocation = userDetails.OfficeLocation,
                        OAuthToken = new OAuthTokenModel
                        {
                            TokenType = authdetails.TokenType,
                            ExpiresIn = authdetails.ExpiresIn,
                            ExpiresOn = authdetails.ExpiresOn,
                            NotBefore = authdetails.NotBefore,
                            AccessToken = authdetails.AccessToken,
                            RefreshToken = authdetails.RefreshToken
                        }
                    };
                    var authdetailscontent = JsonConvert.SerializeObject(payload);
                    return JsonConvert.DeserializeObject<AuthUserModel>(authdetailscontent);
                }
                catch (HttpRequestException e)
                {
                    if (response.StatusCode == HttpStatusCode.NotFound) // 404
                    {
                        throw new UnoEntityNotFoundException(SecurityErrorCode.InvalidToken.GetErrorReferenceDescription(),
                            SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                    }
                    else
                    {
                        throw new UnoHttpException((int)response.StatusCode,
                            e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                    }
                }
            }
        }

        private async Task<string> GetGroupId(string groupName)
        {
            string GroupID = "";
            await ValidateAccessToken().ConfigureAwait(false);
            try
            {
                using (var clientConnection = GetHttpClient())
                {
                    var payload = await clientConnection.GetStringAsync(GraphUrlHelper.GraphGroup).ConfigureAwait(false);
                    var obj = JsonConvert.DeserializeObject<JObject>(payload);
                    if (obj["value"]?.First != null)
                    {
                        var groupId = from g in obj["value"]
                                      where g["displayName"].Value<string>() == groupName
                                      select new
                                      {
                                          ID = g["id"].Value<string>()
                                      };

                        foreach (var result in groupId)
                        {
                            GroupID = result.ID;
                        }
                    }
                }
                return GroupID;
            }
            catch (UnoSecurityException)
            {
                throw;
            }
            catch (NullReferenceException)
            {
                throw new UnoSecurityException(SecurityErrorCode.NullReferenceException, UnoErrorStatus.Internal, "NullReferenceException occured in ValidateAccessToken");
            }
            catch (ArgumentNullException)
            {
                throw new UnoSecurityException(SecurityErrorCode.NullReferenceException, UnoErrorStatus.Internal, "NullReferenceException occured in ValidateAccessToken");
            }
            catch (Exception e)
            {
                throw new UnoBaseException(UnoErrorStatus.Internal, e.Message, "0000");
            }
        }

        public async Task<HttpStatusCode> AddMemberToGroup(string userId, string groupName)
        {
            await ValidateAccessToken().ConfigureAwait(false);

            string GroupID = await GetGroupId(groupName).ConfigureAwait(false);

            try
            {
                using (var clientConnection = GetHttpClient())
                {
                    var AddMemberToGraphUrl = new Uri(string.Format(CultureInfo.InvariantCulture, GraphUrlHelper.GraphAddMemberToGroup, GroupID));
                    string addMemberToGroupURL = string.Format(CultureInfo.InvariantCulture, GraphUrlHelper.GraphAddMemberToGroupPostBody, userId);
                    string postBody = "{\"@odata.id\":\" " + addMemberToGroupURL + "\"}";
                    var postHttpContent = new StringContent(postBody, System.Text.Encoding.UTF8, "application/json");

                    using (var response = clientConnection.PostAsync(AddMemberToGraphUrl, postHttpContent).Result)
                    {
                        try
                        {
                            response.EnsureSuccessStatusCode();
                            return response.StatusCode;
                        }
                        catch (HttpRequestException e)
                        {
                            if (response.StatusCode == HttpStatusCode.NotFound) // 404
                            {
                                throw new UnoEntityNotFoundException(SecurityErrorCode.InvalidToken.GetErrorReferenceDescription(),
                                SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                            }
                            else
                            {
                                throw new UnoHttpException((int)response.StatusCode,
                                    e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                            }
                        }
                    }
                }
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        public async Task<HttpStatusCode> RemoveMemberFromGroup(string userId, string groupName)
        {
            await ValidateAccessToken().ConfigureAwait(false);

            string GroupID = await GetGroupId(groupName).ConfigureAwait(false);

            var removeMemberFromGroupUrl = new Uri(String.Format(CultureInfo.InvariantCulture, GraphUrlHelper.GraphDeleteMemberFromGroup, userId, GroupID));

            try
            {
                using (var clientConnection = GetHttpClient())
                {
                    using (var response = await clientConnection.DeleteAsync(removeMemberFromGroupUrl).ConfigureAwait(false))
                    {
                        try
                        {
                            response.EnsureSuccessStatusCode();
                            return response.StatusCode;
                        }
                        catch (HttpRequestException e)
                        {
                            if (response.StatusCode == HttpStatusCode.NotFound) // 404
                            {
                                throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                    SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                            }
                            else
                            {
                                throw new UnoHttpException((int)response.StatusCode,
                                    e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                            }
                        }
                    }
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        /// <summary>
        ///  Get all/search internal users using Carrier AD
        /// </summary>
        /// <param name="name"></param>
        /// <returns></returns>
        public async Task<List<AdUserBasic>> GetCarrierInternalUsersByName(string name)
        {
            List<AdUserBasic> filterUsersList = new List<AdUserBasic>();
            string[] names = name.Split(' ');
            try
            {

                var graphClientCar = new GraphServiceClient(
                        new DelegateAuthenticationProvider(
                            async (requestMessage) =>
                            {
                                // Set access token to HTTP auth header.
                                requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await GetCarrierAccessToken().ConfigureAwait(false));
                            }));
                string filterStr = names.Length > 1 ? "startswith(givenName,'" + names[0] +
                                    "') and startswith(surname,'" + names[1] + "')" : "startswith(displayName,'" + name +
                                    "') or startswith(mail,'" + name +
                                    "') or startswith(mailNickname,'" + name +
                                    "')";
                var result = await graphClientCar.Users.Request().Top(20).Filter(filterStr).Select("displayName, GivenName, Surname, Mail,userPrincipalName").GetAsync().ConfigureAwait(false);

                foreach (var rec in result)
                {
                    filterUsersList.Add(new AdUserBasic()
                    {
                        Name = string.Format(CultureInfo.InvariantCulture, "{0} {1}", rec.GivenName, rec.Surname),
                        FName = rec.GivenName,
                        LName= rec.Surname,
                        Email = rec.Mail,
                        UserPrincipalName = rec.UserPrincipalName
                    });
                }

                return filterUsersList;
            }
            catch (Exception exception)
            {
                throw new UnoHttpException(UnoErrorStatus.InvalidArgument, exception.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
            }
        }

        /// <summary>
        ///  Get all users using Carrier AD based on domain name
        /// </summary>
        /// <param name="domainName"></param>
        /// <returns></returns>
        public async Task<List<AdUserBasic>> GetCarrierInternalUsersByDomain(string domainName)
        {
            List<AdUserBasic> filterUsersList = new List<AdUserBasic>();
            try
            {

                var graphClientCar = new GraphServiceClient(
                        new DelegateAuthenticationProvider(
                            async (requestMessage) =>
                            {
                                // Set access token to HTTP auth header.
                                requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await GetCarrierAccessToken().ConfigureAwait(false));
                                //requestMessage.Headers.Add("consistencylevel", "eventual");
                            }));
                var options = new List<Option>();
                options.Add(new HeaderOption("ConsistencyLevel", "eventual"));
                options.Add(new QueryOption("$count", "true"));
                string filterStr = "endswith(mail,'" + domainName + "')";
                var result = await graphClientCar.Users.Request(options)
                    .Filter(filterStr).GetAsync().ConfigureAwait(false);

                foreach (var rec in result)
                {
                    if (!string.IsNullOrEmpty(rec.GivenName))
                    {
                        filterUsersList.Add(new AdUserBasic()
                        {
                            Name = string.Format(CultureInfo.InvariantCulture, "{0} {1}", rec.GivenName, rec.Surname),
                            Email = rec.Mail,
                            UserPrincipalName = rec.UserPrincipalName
                        });
                    }
                }

                return filterUsersList;
            }
            catch (Exception exception)
            {
                throw new UnoHttpException(UnoErrorStatus.InvalidArgument, exception.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
            }
        }

        private async Task<string> GetCarrierAccessToken()
        {
            var authority = String.Format(CultureInfo.InvariantCulture, GraphUrlHelper.aadGraphAuthor, carrierAdParameters.TenantId);
            var authContext = new AuthenticationContext(authority);
            var credentials = new ClientCredential(carrierAdParameters.ClientId.ToString(), carrierAdParameters.ClientSecretKey);
            AuthenticationResult authResult = await authContext.AcquireTokenAsync(GraphUrlHelper.aadGraphResource, credentials).ConfigureAwait(false);

            return authResult?.AccessToken;
        }

        private async Task<string> GetB2CAccessToken()
        {
            var authority = String.Format(CultureInfo.InvariantCulture, GraphUrlHelper.aadGraphAuthor, adParameters.TenantId);
            var authContext = new AuthenticationContext(authority);
            var credentials = new ClientCredential(adParameters.ClientId.ToString(), adParameters.ClientSecretKey);
            AuthenticationResult authResult = await authContext.AcquireTokenAsync(GraphUrlHelper.aadGraphResource, credentials).ConfigureAwait(false);

            return authResult?.AccessToken;
        }

        private GraphServiceClient GetCarrierGraphServiceClient()
        {
            try
            {
                if (graphClient == null)
                {
                    graphClient = new GraphServiceClient(
                        new DelegateAuthenticationProvider(
                            async (requestMessage) =>
                            {
                                // Set access token to HTTP auth header.
                                requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await GetCarrierAccessToken().ConfigureAwait(false));
                            }));
                }
            }
            catch (Exception ex)
            {
                throw;
            }

            return graphClient;
        }

        #endregion       

        #region ActiveDirectoryB2CGraphAPI

        private async Task<bool> ValidateB2CAccessToken()
        {
            if (!string.IsNullOrWhiteSpace(b2cAccessToken))
                return true;
            try
            {
                string instance = GraphUrlHelper.aadGraphAuthor;
                string authority = String.Format(CultureInfo.InvariantCulture,
                    instance, adParameters.TenantId);

                AuthenticationContext authContext = new AuthenticationContext(authority);
                ClientCredential clientCredential = new ClientCredential(adParameters.ClientId.ToString(),
                    adParameters.ClientSecretKey);

                AuthenticationResult result = await authContext.AcquireTokenAsync(GraphUrlHelper.aadGraphResourceId,
                    clientCredential).ConfigureAwait(false);

                b2cAccessToken = result.AccessToken;
                if (string.IsNullOrWhiteSpace(b2cAccessToken))
                    throw new UnoSecurityException(SecurityErrorCode.InvalidToken, UnoErrorStatus.Unauthenticated,
                        SecurityErrorCode.InvalidToken.GetErrorReferenceDescription());

                return true;
            }
            catch (UnoSecurityException)
            {
                throw;
            }
            catch (NullReferenceException)
            {
                throw new UnoSecurityException(SecurityErrorCode.NullReferenceException, UnoErrorStatus.Internal, "NullReferenceException occured in ValidateAccessToken");
            }
            catch (ArgumentNullException)
            {
                throw new UnoSecurityException(SecurityErrorCode.NullReferenceException, UnoErrorStatus.Internal, "NullReferenceException occured in ValidateAccessToken");
            }
            catch (AdalServiceException e)
            {
                throw new UnoSecurityException(SecurityErrorCode.AdalServiceException, UnoErrorStatus.Internal,
                    string.Format(CultureInfo.InvariantCulture, "Original Code and Message= {0}: {1}", e.ErrorCode, e.ServiceErrorCodes));
            }
            catch (AdalException e)
            {
                throw new UnoSecurityException(SecurityErrorCode.AdalException, UnoErrorStatus.Internal,
                    string.Format(CultureInfo.InvariantCulture, "Original Code and Message= {0}: {1}", e.ErrorCode, e.Message));
            }
            catch (Exception e)
            {
                throw new UnoBaseException(UnoErrorStatus.Internal, e.Message, "0000");
            }
        }

        private HttpClient GetB2CHttpClient()
        {
            var clientConnection = new HttpClient();
            clientConnection.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", b2cAccessToken);
            return clientConnection;
        }
        public async Task<GraphServiceClient> GetGraphClient()
        {
            GraphServiceClient graphClient = null;
            if (graphClient == null)
            {
                graphClient = new GraphServiceClient(
                    new DelegateAuthenticationProvider(
                        async (requestMessage) =>
                        {
                            // Set access token to HTTP auth header.
                            requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await GetB2CAccessToken().ConfigureAwait(false));
                        }));
            }
            return graphClient;
        }

        public async Task<bool> UpdateAzureAppRedirectUri(GraphServiceClient graphClient, List<string> urls)
        {
            var applications = await graphClient.Applications.Request().GetAsync().ConfigureAwait(false);
            var app = applications.Where(x => x.AppId == adParameters.B2CClientId).FirstOrDefault();
            app.Web.RedirectUris = urls;
            WebApplication webApplication = new WebApplication()
            {
                RedirectUris = urls
            };
            await graphClient.Applications[app.Id].Request().UpdateAsync(new Microsoft.Graph.Application()
            {
                Web = webApplication
            }).ConfigureAwait(false);
            return true;
        }

        public async Task<bool> AddReplyUrl(List<string> appUrls)
        {
            try
            {
                GraphServiceClient graphClient = await GetGraphClient().ConfigureAwait(false);
                List<string> urls = await GetReplyUrl().ConfigureAwait(false);
                appUrls.ForEach(x =>
                {
                    if (!urls.Contains(x))
                    {
                        urls.Add(x);
                    }
                });
                await UpdateAzureAppRedirectUri(graphClient, urls).ConfigureAwait(false);

                return true;
            }
            catch (Exception exception)
            {
                throw new UnoHttpException(UnoErrorStatus.InvalidArgument, exception.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
            }
        }

        public async Task<bool> UpdateReplyUrl(string prevAppUrl, string updatedAppUrl)
        {
            try
            {
                GraphServiceClient graphClient = await GetGraphClient().ConfigureAwait(false);
                List<string> urls = await GetReplyUrl().ConfigureAwait(false);
                // verify if any changes requires in ReplyURL
                if ((urls.Where(rec => rec == prevAppUrl).Count() > 0) && (prevAppUrl != updatedAppUrl))
                {
                    urls.Remove(prevAppUrl);
                    urls.Add(updatedAppUrl);

                    await UpdateAzureAppRedirectUri(graphClient, urls).ConfigureAwait(false);
                }

                return true;
            }
            catch (Exception exception)
            {
                throw new UnoHttpException(UnoErrorStatus.InvalidArgument, exception.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
            }
        }

        public async Task<bool> DeleteReplyUrl(List<string> appUrls)
        {
            try
            {
                GraphServiceClient graphClient = await GetGraphClient().ConfigureAwait(false);
                List<string> deletedUrls = new List<string>();
                List<string> urls = await GetReplyUrl().ConfigureAwait(false);
                appUrls.ForEach(x =>
                {
                    if (urls.Contains(x)) { urls.Remove(x); }
                    else
                    {
                        deletedUrls.Add(x);
                    }
                });
                if (deletedUrls.Count() == appUrls.Count())
                {
                    throw new UnoHttpException(UnoErrorStatus.InvalidArgument, "These urls are already deleted", SecurityErrorCode.HttpError.GetErrorReferenceCode());
                }
                else
                {
                    await UpdateAzureAppRedirectUri(graphClient, urls).ConfigureAwait(false);
                    return true;
                }

            }
            catch (Exception exception)
            {
                throw new UnoHttpException(UnoErrorStatus.InvalidArgument, exception.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
            }
        }

        public async Task<List<string>> GetReplyUrl()
        {
            try
            {
                GraphServiceClient graphClient = await GetGraphClient().ConfigureAwait(false);
                var applications = await graphClient.Applications.Request().GetAsync().ConfigureAwait(false);
                return applications.Where(x => x.AppId == adParameters.B2CClientId).FirstOrDefault().Web.RedirectUris.Select(x => x).ToList(); ;
            }
            catch (Exception exception)
            {
                throw new UnoHttpException(UnoErrorStatus.InvalidArgument, exception.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
            }
        }

        public async Task<bool> UpdateEmailAddress(string objectId, string updatedEmail)
        {
            try
            {
                string json = "{'signInNames': [ {'type': 'emailAddress','value': '" + updatedEmail + "'}] }";
                await client.UpdateUser(objectId, json).ConfigureAwait(false);

                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<AuthUserModel> GetB2CUsers(string query)
        {
            await ValidateB2CAccessToken().ConfigureAwait(false);
            string getUserDetailsURL = string.Empty;

            if (Guid.TryParse(query, out Guid temp))
            {
                getUserDetailsURL = string.Format(CultureInfo.InvariantCulture, GraphUrlHelper.aadGetUserbyId, adParameters.Domain, query);
            }
            else
            {
                getUserDetailsURL = string.Format(CultureInfo.InvariantCulture, GraphUrlHelper.aadGetUserbyUserName, adParameters.Domain, query, query);
            }

            try
            {
                using (var clientConnection = GetB2CHttpClient())
                {
                    AuthUserModel authuser;
                    using (var response = clientConnection.GetAsync(getUserDetailsURL).Result)
                    {
                        try
                        {
                            response.EnsureSuccessStatusCode();
                            var obj = JsonConvert.DeserializeObject<JObject>(response.Content.ReadAsStringAsync().Result);
                            if (obj["value"]?.First == null)
                            {
                                throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                    SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                            }
                            authuser = JsonConvert.DeserializeObject<AuthB2CUserListModel>(obj.ToString()).Value.First();
                            return authuser;
                        }
                        catch (HttpRequestException e)
                        {
                            if (response.StatusCode == HttpStatusCode.NotFound) // 404
                            {
                                throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                    SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                            }
                            else
                            {
                                throw new UnoHttpException((int)response.StatusCode,
                                    e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                            }
                        }
                    }
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        public async Task<AuthB2CUserListModel> GetUsersBySearch(string query)
        {
            await ValidateB2CAccessToken().ConfigureAwait(false);
            string getUserDetailsURL = string.Empty;

            if (Guid.TryParse(query, out Guid temp))
            {
                getUserDetailsURL = string.Format(CultureInfo.InvariantCulture, GraphUrlHelper.aadGetUserbyId, adParameters.Domain, query);
            }
            else
            {
                getUserDetailsURL = string.Format(CultureInfo.InvariantCulture, GraphUrlHelper.aadGetallUsers, adParameters.Domain, query);
            }

            try
            {
                using (var clientConnection = GetB2CHttpClient())
                {
                    AuthB2CUserListModel authuser;
                    using (var response = clientConnection.GetAsync(new Uri(getUserDetailsURL)).Result)
                    {
                        try
                        {
                            response.EnsureSuccessStatusCode();
                            var obj = JsonConvert.DeserializeObject<JObject>(response.Content.ReadAsStringAsync().Result);
                            authuser = JsonConvert.DeserializeObject<AuthB2CUserListModel>(obj.ToString());
                            return authuser;
                        }
                        catch (HttpRequestException e)
                        {
                            if (response.StatusCode == HttpStatusCode.NotFound) // 404
                            {
                                throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                    SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                            }
                            else
                            {
                                throw new UnoHttpException((int)response.StatusCode,
                                    e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                            }
                        }
                    }
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        public async Task<AuthUserModel> AuthenticateB2CUser(string userName, string password)
        {
            string authUrl = String.Format(CultureInfo.InvariantCulture, adParameters.B2CAuthUrl, adParameters.Domain);
            var oauthEndpoint = new Uri(string.Concat(authUrl, "?p=", adParameters.ROPC));
            try
            {
                var userAdDetails = await GetB2CUsers(userName).ConfigureAwait(false);
                using (var clientConnection = new HttpClient())
                {
                    var response = await clientConnection.PostAsync(oauthEndpoint, new FormUrlEncodedContent(new[]
                    {
                            new KeyValuePair<string, string>("response_type", "id_token"),
                            new KeyValuePair<string, string>("client_id",  adParameters.B2CNativeClient),
                            new KeyValuePair<string, string>("grant_type", "password"),
                            new KeyValuePair<string, string>("username", userName),
                            new KeyValuePair<string, string>("password", password),
                            new KeyValuePair<string, string>("scope", string.Concat("openid ",adParameters.B2CNativeClient," offline_access")),
                        })).ConfigureAwait(false);

                    response.EnsureSuccessStatusCode();
                    var content = await response.Content.ReadAsAsync<OAuthTokenModel>().ConfigureAwait(false);
                    var userDbDetails = await GetUserDetailsFromDatabase(userAdDetails.objectId).ConfigureAwait(false);

                    var payload = new AuthUserModel
                    {
                        Username = userName,
                        objectId = userAdDetails.objectId,
                        RoleName = userDbDetails.RoleName,
                        GivenName = userAdDetails.GivenName,
                        Surname = userAdDetails.Surname,
                        MobilePhone = userDbDetails.MobilePhone,
                        OfficeLocation = userDbDetails.OfficeLocation,
                        Email = userDbDetails.EmailAddress,
                        OAuthToken = new OAuthTokenModel
                        {
                            TokenType = content.TokenType,
                            ExpiresIn = content.ExpiresIn,
                            ExpiresOn = content.ExpiresOn,
                            NotBefore = content.NotBefore,
                            AccessToken = content.AccessToken,
                            RefreshToken = content.RefreshToken,
                            IdToken = content.IdToken
                        }
                    };

                    var authdetailscontent = JsonConvert.SerializeObject(payload);
                    return JsonConvert.DeserializeObject<AuthUserModel>(authdetailscontent);
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        public async Task<OAuthTokenModel> GetRefreshToken(string refreshToken)
        {
            string authUrl = String.Format(CultureInfo.InvariantCulture, adParameters.B2CAuthUrl, adParameters.TenantId);
            var oauthEndpoint = new Uri(string.Concat(authUrl, "?p=", adParameters.ROPC));

            using (var clientConnection = new HttpClient())
            {
                clientConnection.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                OAuthTokenModel oauthTokenDetails;

                var response = await clientConnection.PostAsync(oauthEndpoint, new FormUrlEncodedContent(new[]
                {
                            new KeyValuePair<string, string>("response_type", "id_token"),
                            new KeyValuePair<string, string>("client_id",  adParameters.B2CClientId),
                            new KeyValuePair<string, string>("grant_type", "refresh_token"),
                            new KeyValuePair<string, string>("resource", adParameters.B2CClientId),
                            new KeyValuePair<string, string>("refresh_token", refreshToken),
                        })).ConfigureAwait(false);

                try
                {
                    response.EnsureSuccessStatusCode();
                    oauthTokenDetails = await response.Content.ReadAsAsync<OAuthTokenModel>().ConfigureAwait(false);
                    return oauthTokenDetails;
                }
                catch (HttpRequestException e)
                {
                    if (response.StatusCode == HttpStatusCode.NotFound) // 404
                    {
                        throw new UnoEntityNotFoundException(SecurityErrorCode.InvalidToken.GetErrorReferenceDescription(),
                            SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                    }
                    else
                    {
                        throw new UnoHttpException((int)response.StatusCode,
                            e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                    }
                }
            }
        }

        public async Task<HttpStatusCode> CreateB2CUser1(UserSignUpModel signupuserdetails)
        {
            await ValidateB2CAccessToken().ConfigureAwait(false);
            string createUserUrl;
            try
            {
                using (var clientConnection = GetB2CHttpClient())
                {
                    UserSignUpModel user;
                    using (var stream = new MemoryStream())
                    {
                        using (var writer = new StreamWriter(stream))
                        {
                            var payload = new B2CUserSignUpDetailsModel
                            {
                                accountEnabled = true,
                                signInNames = new List<SignInNamesModel>()
                                {
                                    new SignInNamesModel { Type = "emailAddress", Value = signupuserdetails.Email }
                                },
                                creationType = "LocalAccount",
                                displayName = signupuserdetails.FirstName,
                                mailNickname = signupuserdetails.FirstName,
                                passprofile = new PasswordProfileModel
                                {
                                    ForceChangePasswordNextLogin = true,
                                    Password = signupuserdetails.Password
                                },
                                passwordPolicies = "DisablePasswordExpiration"
                            };

                            var userdetails = JsonConvert.SerializeObject(payload, Newtonsoft.Json.Formatting.None,
                            new JsonSerializerSettings
                            {
                                NullValueHandling = NullValueHandling.Ignore
                            });

                            writer.Write(userdetails);
                            writer.Flush();
                            stream.Flush();
                            stream.Position = 0;

                            using (var content = new StreamContent(stream))
                            {
                                content.Headers.Add("Content-Type", "application/json");
                                createUserUrl = string.Concat(GraphUrlHelper.aadGraphResourceId, adParameters.Domain, "/users", "?", GraphUrlHelper.aadGraphVersion);

                                using (var response = clientConnection.PostAsync(createUserUrl, content).Result)
                                {
                                    try
                                    {
                                        response.EnsureSuccessStatusCode();

                                        user = response.Content.ReadAsAsync<UserSignUpModel>().Result;

                                        signupuserdetails.UserPrincipalName = user.UserPrincipalName;

                                        var updatedUserDetailsRequestStatus = await UpdateB2CUser1(signupuserdetails).ConfigureAwait(false);

                                        if (updatedUserDetailsRequestStatus == HttpStatusCode.NoContent)
                                        {
                                            return response.StatusCode;
                                        }
                                        else
                                        {
                                            throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                                SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                                        }
                                    }
                                    catch (HttpRequestException e)
                                    {
                                        if (response.StatusCode == HttpStatusCode.NotFound) // 404
                                        {
                                            throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                                SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                                        }
                                        else
                                        {
                                            throw new UnoHttpException((int)response.StatusCode,
                                                e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }

        }

        public async Task<HttpStatusCode> UpdateB2CUser1(UserSignUpModel userdetails)
        {
            await ValidateB2CAccessToken().ConfigureAwait(false);
            try
            {
                var updateUserDetailsUrl = string.Concat(GraphUrlHelper.aadGraphResourceId, adParameters.Domain, "/users/", userdetails.UserPrincipalName, "?", GraphUrlHelper.aadGraphVersion);
                using (var clientConnection = GetB2CHttpClient())
                {
                    using (var stream = new MemoryStream())
                    {
                        using (var writer = new StreamWriter(stream))
                        {
                            var payload = new
                            {
                                givenName = userdetails.FirstName,
                                surname = userdetails.SurName,
                                country = userdetails.Country,
                                state = userdetails.State,
                                city = userdetails.City,
                                postalCode = userdetails.PostalCode
                            };

                            var userupdatedetails = JsonConvert.SerializeObject(payload, Newtonsoft.Json.Formatting.None,
                                new JsonSerializerSettings
                                {
                                    NullValueHandling = NullValueHandling.Ignore
                                });

                            writer.Write(userupdatedetails);
                            writer.Flush();
                            stream.Flush();
                            stream.Position = 0;

                            using (var content = new StreamContent(stream))
                            {
                                content.Headers.Add("Content-Type", "application/json");

                                using (var response = clientConnection.PatchAsync(updateUserDetailsUrl, content).Result)
                                {
                                    try
                                    {
                                        response.EnsureSuccessStatusCode();
                                        return response.StatusCode;
                                    }
                                    catch (HttpRequestException e)
                                    {
                                        if (response.StatusCode == HttpStatusCode.NotFound) // 404
                                        {
                                            throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                                                SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                                        }
                                        else
                                        {
                                            throw new UnoHttpException((int)response.StatusCode,
                                                e.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        public async Task<UserDetailsModel> GetUserDetailsFromDatabase(string objectId)
        {
            try
            {
                using (UnoContext dbEntities = new UnoContext(awsManagerReadKey))
                {
                    var result = dbEntities.Users.Where(u => u.UnifyId == Guid.Parse(objectId)).FirstOrDefault();
                    UserDetailsModel userdetails = result != null ? new UserDetailsModel() { GivenName = result.FirstName, SurName = result.LastName } : null;
                    return userdetails;
                }
            }
            catch (System.Data.SqlClient.SqlException ex)
            {
                throw new UnoHttpException(UnoErrorStatus.InvalidArgument,
                                    string.Format(CultureInfo.InvariantCulture, "ServiceDownError:--> {0} and Error mesage --> {1}", ex.InnerException, ex.Message), SecurityErrorCode.HttpError.GetErrorReferenceCode());
            }
            catch (Exception ex)
            {
                throw new UnoHttpException(UnoErrorStatus.InvalidArgument, ex.Message, SecurityErrorCode.HttpError.GetErrorReferenceCode());
            }
        }

        public async Task<HttpStatusCode> CreateB2CUser(BaseUserSignUpDetailsModel signupuserdetails)
        {
            try
            {
                var updatedUserDetailsRequestStatus = await UpdateB2CUser(signupuserdetails).ConfigureAwait(false);
                if (updatedUserDetailsRequestStatus == HttpStatusCode.NoContent)
                {
                    return HttpStatusCode.Created;
                }
                else
                {
                    throw new UnoHttpException(UnoErrorStatus.PermissionDenied, "Unable to create user in Active Directory", SecurityErrorCode.HttpError.GetErrorReferenceCode());
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        public async Task<HttpStatusCode> UpdateB2CUser(BaseUserSignUpDetailsModel userdetails)
        {
            try
            {
                var getb2cUserDetails = JsonConvert.DeserializeObject<JObject>(client.GetUserByEmailId(userdetails.Email).Result);

                if (getb2cUserDetails["value"]?.First == null)
                {
                    throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                        SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                }
                var userinfo = JsonConvert.DeserializeObject<UserSignUpModel>(getb2cUserDetails["value"]?.First.ToString());


                var payload = new
                {
                    givenName = userdetails.FirstName,
                    surname = userdetails.SurName,
                    country = userdetails.Country,
                    state = userdetails.State,
                    city = userdetails.City,
                    postalCode = userdetails.PostalCode
                };

                var userupdatedetails = JsonConvert.SerializeObject(payload, Formatting.Indented,
                    new JsonSerializerSettings
                    {
                        NullValueHandling = NullValueHandling.Ignore
                    });

                await client.UpdateUser(userinfo.UserPrincipalName, userupdatedetails.ToString()).ConfigureAwait(false);
                return HttpStatusCode.NoContent;
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }
        public async Task<string> GetB2CUser(string email)
        {
            try
            {
                string userinfo = null;
                var getb2cUserDetails = JsonConvert.DeserializeObject<JObject>(client.GetUserByEmailId(email).Result);
                userinfo = getb2cUserDetails["value"]?.First == null ? userinfo : JsonConvert.DeserializeObject<UserSignUpModel>(getb2cUserDetails["value"]?.First.ToString()).UserPrincipalName;
                return userinfo;
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }
        public async Task<UserCloudModel> GetB2CExternalUser(string email)
        {
            try
            {
                UserCloudModel userinfo = null;
                var getb2cUserDetails = JsonConvert.DeserializeObject<JObject>(client.GetUserByEmailId(email).Result);
                userinfo = getb2cUserDetails["value"]?.First == null ? userinfo : JsonConvert.DeserializeObject<UserCloudModel>(getb2cUserDetails["value"]?.First.ToString());
                return userinfo;
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        public async Task<HttpStatusCode> DeleteB2cUser(string email)
        {
            try
            {
                if (email == null)
                {
                    throw new ArgumentNullException(nameof(email));
                }

                var getb2cUserDetails = JsonConvert.DeserializeObject<JObject>(client.GetUserByEmailId(email).Result);

                if (getb2cUserDetails["value"]?.First == null)
                {
                    throw new UnoEntityNotFoundException(SecurityErrorCode.UserNotFound.GetErrorReferenceDescription(),
                        SecurityErrorCode.UserNotFound.GetErrorReferenceCode());
                }
                var userinfo = JsonConvert.DeserializeObject<UserSignUpModel>(getb2cUserDetails["value"]?.First.ToString());

                await client.DeleteUser(userinfo.UserPrincipalName).ConfigureAwait(false);
                return HttpStatusCode.NoContent;
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, e.Message);
            }
        }

        /// <summary>
        /// Authenticate a user and generate access token
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        /// <exception cref="UnoSecurityException"></exception>
        public async Task<AuthUserModel> AuthenticateCognitoUser(string userName, string password, string appUrl = "")
        {
            UsersInfoModel response = null;
            try
            {
                {
                    AmazonCognitoIdentityProviderClient provider =
                    new AmazonCognitoIdentityProviderClient(new Amazon.Runtime.AnonymousAWSCredentials(), RegionEndpoint.USEast2);
                    CognitoUserPool userPool = new CognitoUserPool(cognitoUserLogin.UserPoolId, cognitoUserLogin.AwsClientId, provider);
                    CognitoUser user = new CognitoUser(userName, cognitoUserLogin.AwsClientId, userPool, provider);
                    InitiateSrpAuthRequest authRequest = new InitiateSrpAuthRequest()
                    {
                        Password = password
                    };

                    AuthFlowResponse authResponse = await user.StartWithSrpAuthAsync(authRequest).ConfigureAwait(false);
                    accessToken = authResponse.AuthenticationResult.IdToken;
                    response= await new UsersDataService(awsManagerReadKey).GetUserId(userName).ConfigureAwait(false);
                    
                    List<Claim> claimList = ((JwtSecurityToken)new JwtSecurityTokenHandler().ReadToken(accessToken)).Claims.ToList();
                    var claims = new[] {
                        new Claim(Constant.Sub, claimList.FirstOrDefault(x => x.Type == Constant.Sub).Value),
                        new Claim(Constant.AuthTime, claimList.FirstOrDefault(x => x.Type == Constant.AuthTime).Value),
                        new Claim(Constant.Iat, claimList.FirstOrDefault(x => x.Type == Constant.Iat).Value),
                        new Claim(Constant.Ver, Constant.VerValue),
                        new Claim(Constant.Iss, claimList.FirstOrDefault(x => x.Type == Constant.Iss).Value),
                        new Claim(Constant.Aud, claimList.FirstOrDefault(x => x.Type == Constant.Aud).Value),
                        new Claim(Constant.Idp, claimList.FirstOrDefault(x => x.Type == Constant.Idp)!=null?claimList.FirstOrDefault(x => x.Type == Constant.Idp).Value:  claimList.FirstOrDefault(x => x.Type == Constant.Iss).Value),
                        new Claim(Constant.GivenName, claimList.FirstOrDefault(x => x.Type == Constant.GivenName).Value),
                        new Claim(Constant.FamilyName, claimList.FirstOrDefault(x => x.Type == Constant.FamilyName).Value),
                        new Claim(Constant.Name, claimList.FirstOrDefault(x => x.Type == Constant.FamilyName).Value),
                        //new Claim(Constant.Oid, claimList.FirstOrDefault(x => x.Type == Constant.CustomOid) != null ?claimList.FirstOrDefault(x => x.Type == Constant.CustomOid).Value:claimList.FirstOrDefault(x => x.Type == Constant.Sub).Value),
                        new Claim(Constant.Oid, response.ObjectId.ToString()),
                        new Claim(Constant.Country,claimList.FirstOrDefault(x => x.Type == Constant.CustomCountry)!=null ? claimList.FirstOrDefault(x => x.Type == Constant.CustomCountry).Value:""),
                        new Claim(Constant.Emails, claimList.FirstOrDefault(x => x.Type == Constant.Email).Value ),
                        new Claim(Constant.UserType, Constant.External),
                        new Claim(Constant.UserName, claimList.FirstOrDefault(x => x.Type == Constant.CognitoUserName)!=null?  claimList.FirstOrDefault(x => x.Type == Constant.CognitoUserName).Value:""),
                        new Claim(Constant.HvacUserName, Constant.HvacUserNameValue),
                        new Claim(Constant.Privileges, response.IsManager.ToString()),
                        new Claim(Constant.AppPrivileges, response.IsAppManager.ToString()),
                        new Claim(Constant.AppUrl, CryptoUtil.EncryptString(appUrl)),
                        new Claim(Constant.UserId,response.Id.ToString()),
                    };

                    var securityKey = Encoding.ASCII.GetBytes(cognitoUserLogin.AwsSecret);
                    var signingKey = new SymmetricSecurityKey(securityKey);
                    SigningCredentials signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

                    // Create the signing credetails for JWT
                    JwtSecurityToken token = new JwtSecurityToken(
                            string.Empty,
                            string.Empty,
                            claims,
                            DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(claimList.FirstOrDefault(x => x.Type == Constant.Iat).Value)).DateTime,
                            DateTimeOffset.FromUnixTimeSeconds(Convert.ToInt64(claimList.FirstOrDefault(x => x.Type == Constant.Exp).Value)).DateTime,
                            signingCredentials);

                    // Get the representation of the signed token
                    JwtSecurityTokenHandler jwtHandler = new JwtSecurityTokenHandler();
                    string jwtOnTheWire = jwtHandler.WriteToken(token);

                    var payload = new AuthUserModel
                    {
                        Username = userName,
                        RoleName = null,
                        objectId = response.ObjectId.ToString(), //claimList.FirstOrDefault(x => x.Type == Constant.CustomOid) != null ? claimList.FirstOrDefault(x => x.Type == Constant.CustomOid).Value : claimList.FirstOrDefault(x => x.Type == Constant.Sub).Value,
                        GivenName = claimList.FirstOrDefault(x => x.Type == Constant.GivenName).Value,
                        Surname = claimList.FirstOrDefault(x => x.Type == Constant.FamilyName).Value,
                        Email = claimList.FirstOrDefault(x => x.Type == Constant.Email).Value,
                        MobilePhone = null,
                        OfficeLocation = null,
                        OAuthToken = new OAuthTokenModel
                        {
                            TokenType = Constant.TokenType,
                            ExpiresIn = 0,
                            ExpiresOn = 0,
                            NotBefore = 0,
                            RefreshToken = string.Empty,
                            IdToken = string.Empty,
                            AccessToken = jwtOnTheWire
                        }
                    };

                    var authdetailscontent = JsonConvert.SerializeObject(payload);
                    return JsonConvert.DeserializeObject<AuthUserModel>(authdetailscontent);
                }
            }
            catch (UnoHttpException)
            {
                throw;
            }
            catch (UnoEntityNotFoundException)
            {
                throw;
            }
            catch (Exception e)
            {
                string statusMsg = string.Empty;
                if (e.Message.Contains("password") || response == null)
                {
                    // If incorrect username or password then update no of attempts
                    var user = await new UsersDataService(awsManagerReadKey).GetupdateSignInAttempts(userName);
                    if (user?.NoOFAttempts == 5) //Account locked
                    {   
                        // Send email to unlock account
                        user.Status = await new CommonBiz().SendAccountLockEmail(user, userName);
                        statusMsg = Constant.SIGNIN_ATTEMPT_EXCEED;
                    }
                    else
                        statusMsg = string.Format(Constant.SIGNIN_INVALID_CRED, 5 - user?.NoOFAttempts);
                }
                else if (e.Message.Contains("instructions"))
                {
                    statusMsg = Constant.SIGNIN_ATTEMPT_EXCEED;
                }

                throw new UnoSecurityException(SecurityErrorCode.UserFetchError, string.IsNullOrEmpty(statusMsg)? e.Message : statusMsg);
            }
        }

        #endregion
    }
}
