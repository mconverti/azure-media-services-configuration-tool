using System;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

using Microsoft.WindowsAzure.MediaServices.Client;
using Microsoft.WindowsAzure.MediaServices.Client.ContentKeyAuthorization;

namespace AzureMediaServicesConfigurationTool
{
    public class Program
    {
        private static string ContentKeyAuthorizationPolicyRestrictionName = "JwtContentKeyAuthorizationPolicyRestriction";

        private static int CommonEncryptionContentKeyLength = 16;
        private static string CommonEncryptionContentKeyName = "CommonEncryptionContentKey";

        public static async Task Main(string[] args)
        {
            var context = CreateCloudMediaContext();

            // TODO: Scale Streaming Endpoint?
            // TODO: Scale Encoding Units?
            
            var jwtRestriction = GetContentKeyAuthorizationPolicyRestriction();

            // Configure Widevine
            await CreateOrUpdateWidevinePoliciesAsync(context, jwtRestriction);

            // TODO: Configure PlayReady

            // TODO: Configure FairPlay
        }

        private static CloudMediaContext CreateCloudMediaContext()
        {
            var tenant = ConfigurationManager.AppSettings["AMSAADTenantDomain"];
            var endpoint = ConfigurationManager.AppSettings["AMSRESTAPIEndpoint"];
            var clientId = ConfigurationManager.AppSettings["AMSRESTAPIClientId"];
            var clientSecret = ConfigurationManager.AppSettings["AMSRESTAPIClientSecret"];

            var tokenCredentials = new AzureAdTokenCredentials(tenant,
                new AzureAdClientSymmetricKey(clientId, clientSecret),
                AzureEnvironments.AzureCloudEnvironment);

            var tokenProvider = new AzureAdTokenProvider(tokenCredentials);

            return new CloudMediaContext(new Uri(endpoint), tokenProvider);
        }

        private static ContentKeyAuthorizationPolicyRestriction GetContentKeyAuthorizationPolicyRestriction()
        {
            return new ContentKeyAuthorizationPolicyRestriction
            {
                Name = ContentKeyAuthorizationPolicyRestrictionName,
                KeyRestrictionType = (int)ContentKeyRestrictionType.TokenRestricted,
                Requirements = GetJwtRequirements(),
            };
        }

        private static string GetJwtRequirements()
        {
            var primaryVerificationKey = ConfigurationManager.AppSettings["JWTRestrictionPrimaryVerificationKey"];
            var audience = ConfigurationManager.AppSettings["JWTRestrictionAudience"];
            var issuer = ConfigurationManager.AppSettings["JWTRestrictionIssuer"];

            var template = new TokenRestrictionTemplate(TokenType.JWT)
            {
                PrimaryVerificationKey = new SymmetricVerificationKey(EncodeUtilities.Base64UrlDecode(primaryVerificationKey)),
                Audience = audience,
                Issuer = issuer
            };

            return TokenRestrictionTemplateSerializer.Serialize(template);
        }

        private static async Task CreateOrUpdateWidevinePoliciesAsync(MediaContextBase context, ContentKeyAuthorizationPolicyRestriction jwtRestriction)
        {
            var authorizationPolicyName = ConfigurationManager.AppSettings["CommonEncryptionAuthorizationPolicyName"];
            var authorizationPolicyOptionName = ConfigurationManager.AppSettings["WidevineAuthorizationPolicyOptionName"];

            var deliveryPolicyName = ConfigurationManager.AppSettings["DynamicCommonEncryptionDeliveryPolicyName"];
            var licenseTemplatePath = ConfigurationManager.AppSettings["WidevineLicenseTemplatePath"];

            var authorizationPolicy = context.ContentKeyAuthorizationPolicies.Where(p => p.Name == authorizationPolicyName).FirstOrDefault();
            if (authorizationPolicy == null)
            {
                
            }

            var key = await GetOrCreateCommonEncryptionContentKey(context);

            // TODO
        }

        private static async Task<IContentKey> GetOrCreateCommonEncryptionContentKey(MediaContextBase context)
        {
            var key = context.ContentKeys.Where(c => c.ContentKeyType == ContentKeyType.CommonEncryption).FirstOrDefault();

            if (key == null)
            {
                var keyId = Guid.NewGuid();
                var contentKey = GetRandomBuffer(CommonEncryptionContentKeyLength);

                key = await context.ContentKeys.CreateAsync(keyId, contentKey, CommonEncryptionContentKeyName, ContentKeyType.CommonEncryption);
            }

            return key;
        }

        private static byte[] GetRandomBuffer(int length)
        {
            var returnValue = new byte[length];

            using (var rng = new RNGCryptoServiceProvider())
            {
                rng.GetBytes(returnValue);
            }

            return returnValue;
        }
    }
}
