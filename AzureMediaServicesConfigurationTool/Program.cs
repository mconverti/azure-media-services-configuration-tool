using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

using Microsoft.WindowsAzure.MediaServices.Client;
using Microsoft.WindowsAzure.MediaServices.Client.ContentKeyAuthorization;
using Microsoft.WindowsAzure.MediaServices.Client.DynamicEncryption;

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
            var restrictions = new List<ContentKeyAuthorizationPolicyRestriction> { jwtRestriction };

            // Configure Common Encryption polices: Widevine + PlayReady
            await CreateCommonEncryptionPoliciesAsync(context, restrictions);

            // TODO: Configure Common Encryption CBCS polices: FairPlay
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

        private static async Task CreateCommonEncryptionPoliciesAsync(MediaContextBase context, List<ContentKeyAuthorizationPolicyRestriction> restrictions)
        {
            // Content Key Authorization Policy
            var authorizationPolicyName = ConfigurationManager.AppSettings["CommonEncryptionAuthorizationPolicyName"];
            var authorizationPolicy = context.ContentKeyAuthorizationPolicies.Where(p => p.Name == authorizationPolicyName).FirstOrDefault();
            if (authorizationPolicy == null)
            {
                authorizationPolicy = await context.ContentKeyAuthorizationPolicies.CreateAsync(authorizationPolicyName);
            }

            var widevineAuthorizationPolicyOptionName = ConfigurationManager.AppSettings["WidevineAuthorizationPolicyOptionName"];
            var widevineLicenseTemplatePath = ConfigurationManager.AppSettings["WidevineLicenseTemplatePath"];
            var widevineLicenseTemplate = File.ReadAllText(widevineLicenseTemplatePath);
            var widevineAuthorizationPolicyOption = authorizationPolicy.Options.Where(o => o.Name == widevineAuthorizationPolicyOptionName).FirstOrDefault();
            if (widevineAuthorizationPolicyOption == null)
            {
                widevineAuthorizationPolicyOption = await context.ContentKeyAuthorizationPolicyOptions.CreateAsync(
                    widevineAuthorizationPolicyOptionName,
                    ContentKeyDeliveryType.Widevine,
                    restrictions,
                    widevineLicenseTemplate);

                authorizationPolicy.Options.Add(widevineAuthorizationPolicyOption);
            }
            else
            {
                widevineAuthorizationPolicyOption.KeyDeliveryType = ContentKeyDeliveryType.Widevine;
                widevineAuthorizationPolicyOption.Restrictions = restrictions;
                widevineAuthorizationPolicyOption.KeyDeliveryConfiguration = widevineLicenseTemplate;

                await widevineAuthorizationPolicyOption.UpdateAsync();
            }

            var playReadyAuthorizationPolicyOptionName = ConfigurationManager.AppSettings["PlayReadyAuthorizationPolicyOptionName"];
            var playReadyLicenseTemplatePath = ConfigurationManager.AppSettings["PlayReadyLicenseTemplatePath"];
            var playReadyLicenseTemplate = File.ReadAllText(playReadyLicenseTemplatePath);
            var playReadyAuthorizationPolicyOption = authorizationPolicy.Options.Where(o => o.Name == playReadyAuthorizationPolicyOptionName).FirstOrDefault();
            if (playReadyAuthorizationPolicyOption == null)
            {
                playReadyAuthorizationPolicyOption = await context.ContentKeyAuthorizationPolicyOptions.CreateAsync(
                    playReadyAuthorizationPolicyOptionName,
                    ContentKeyDeliveryType.PlayReadyLicense,
                    restrictions,
                    playReadyLicenseTemplate);

                authorizationPolicy.Options.Add(playReadyAuthorizationPolicyOption);
            }
            else
            {
                playReadyAuthorizationPolicyOption.KeyDeliveryType = ContentKeyDeliveryType.PlayReadyLicense;
                playReadyAuthorizationPolicyOption.Restrictions = restrictions;
                playReadyAuthorizationPolicyOption.KeyDeliveryConfiguration = playReadyLicenseTemplate;

                await playReadyAuthorizationPolicyOption.UpdateAsync();
            }

            // Asset Delivery Policy
            var commonEncryptionKey = await GetOrCreateCommonEncryptionContentKey(context);
            var playReadyLicenseAcquisitionUri = await commonEncryptionKey.GetKeyDeliveryUrlAsync(ContentKeyDeliveryType.PlayReadyLicense);
            var widevineUri = (new UriBuilder(await commonEncryptionKey.GetKeyDeliveryUrlAsync(ContentKeyDeliveryType.Widevine)) { Query = string.Empty }).Uri;
            await commonEncryptionKey.DeleteAsync();

            var deliveryPolicyConfiguration = new Dictionary<AssetDeliveryPolicyConfigurationKey, string>
            {
                { AssetDeliveryPolicyConfigurationKey.PlayReadyLicenseAcquisitionUrl, playReadyLicenseAcquisitionUri.ToString() },
                { AssetDeliveryPolicyConfigurationKey.WidevineBaseLicenseAcquisitionUrl, widevineUri.ToString() }
            };
            var deliveryPolicyName = ConfigurationManager.AppSettings["DynamicCommonEncryptionDeliveryPolicyName"];
            var deliveryPolicy = context.AssetDeliveryPolicies.Where(p => p.Name == deliveryPolicyName).FirstOrDefault();
            if (deliveryPolicy == null)
            {
                deliveryPolicy = await context.AssetDeliveryPolicies.CreateAsync(
                    deliveryPolicyName,
                    AssetDeliveryPolicyType.DynamicCommonEncryption,
                    AssetDeliveryProtocol.Dash,
                    deliveryPolicyConfiguration);
            }
            else
            {
                deliveryPolicy.AssetDeliveryPolicyType = AssetDeliveryPolicyType.DynamicCommonEncryption;
                deliveryPolicy.AssetDeliveryProtocol = AssetDeliveryProtocol.Dash;
                deliveryPolicy.AssetDeliveryConfiguration = deliveryPolicyConfiguration;

                await deliveryPolicy.UpdateAsync();
            }
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
