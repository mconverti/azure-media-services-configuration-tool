using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

using Microsoft.WindowsAzure.MediaServices.Client;
using Microsoft.WindowsAzure.MediaServices.Client.ContentKeyAuthorization;
using Microsoft.WindowsAzure.MediaServices.Client.DynamicEncryption;
using Microsoft.WindowsAzure.MediaServices.Client.FairPlay;
using Newtonsoft.Json;

namespace AzureMediaServicesConfigurationTool
{
    public static class Program
    {
        private const string ContentKeyPrefix = "nb:kid:UUID:";
        private const string ContentKeyAuthorizationPolicyRestrictionName = "jwt_content_key_authorization_policy_restriction";

        private const string CommonEncryptionContentKeyName = "common_encryption_content_key";
        private const string CommonEncryptionCbcsContentKeyName = "common_encryption_cbcs_content_key";
        private const int CommonEncryptionContentKeyLength = 16;

        public static async Task Main(string[] args)
        {
            try
            {
                Console.WriteLine("Azure Media Services Configuration Tool");
                Console.WriteLine("=======================================");
                Console.WriteLine();

                Console.WriteLine("Creating Azure Media Services context...");
                var context = CreateCloudMediaContext();
                Console.WriteLine("Azure Media Services context created.");

                // TODO: Scale Streaming Endpoint?
                // TODO: Scale Encoding Units?

                Console.WriteLine("Getting JWT restriction configuration...");
                var restrictions = new List<ContentKeyAuthorizationPolicyRestriction> { GetContentKeyAuthorizationPolicyRestriction() };
                Console.WriteLine("JWT restriction configuration ready.");

                Console.WriteLine("Applying Common Encryption (Widevine + PlayReady) policies...");
                await CreateCommonEncryptionPoliciesAsync(context, restrictions);
                Console.WriteLine("Common Encryption (Widevine + PlayReady) policies applied.");

                Console.WriteLine("Applying Common Encryption CBCS (FairPlay) policies...");
                await CreateCommonEncryptionCbcsPoliciesAsync(context, restrictions);
                Console.WriteLine("Common Encryption CBCS (FairPlay) policies applied.");
            }
            catch (Exception exception)
            {
                Console.Error.WriteLine($"There was an error when applying the configuration. {exception.ToString()}");
            }

            Console.WriteLine();
            Console.WriteLine("Done.");
            Console.ReadKey();
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
            var widevineLicenseTemplate = GetWidevineLicenseTemplateConfiguration();
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
            var playReadyLicenseTemplate = GetPlayReadyLicenseTemplateConfiguration();
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
            var commonEncryptionKey = await CreateCommonEncryptionContentKeyAsync(context);
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
                    (AssetDeliveryProtocol.Dash | AssetDeliveryProtocol.SmoothStreaming),
                    deliveryPolicyConfiguration);
            }
            else
            {
                deliveryPolicy.AssetDeliveryPolicyType = AssetDeliveryPolicyType.DynamicCommonEncryption;
                deliveryPolicy.AssetDeliveryProtocol = (AssetDeliveryProtocol.Dash | AssetDeliveryProtocol.SmoothStreaming);
                deliveryPolicy.AssetDeliveryConfiguration = deliveryPolicyConfiguration;

                await deliveryPolicy.UpdateAsync();
            }
        }

        private static async Task CreateCommonEncryptionCbcsPoliciesAsync(MediaContextBase context, List<ContentKeyAuthorizationPolicyRestriction> restrictions)
        {
            var fairPlayEnabled = bool.Parse(ConfigurationManager.AppSettings["FairPlayEnabled"]);

            if (!fairPlayEnabled)
            {
                Console.WriteLine("Skipping Common Encryption CBCS (FairPlay) policies configuration (disabled by conf)");
                return;
            }

            // Content Key Authorization Policy
            var authorizationPolicyName = ConfigurationManager.AppSettings["CommonEncryptionCbcsAuthorizationPolicyName"];
            var authorizationPolicy = context.ContentKeyAuthorizationPolicies.Where(p => p.Name == authorizationPolicyName).FirstOrDefault();

            if (authorizationPolicy == null)
            {
                authorizationPolicy = await context.ContentKeyAuthorizationPolicies.CreateAsync(authorizationPolicyName);
            }

            var fairPlayAuthorizationPolicyOptionName = ConfigurationManager.AppSettings["FairPlayAuthorizationPolicyOptionName"];
            var fairPlayConfiguration = await GetFairPlayConfigurationAsync(context);
            var fariPlayAuthorizationPolicyOption = authorizationPolicy.Options.Where(o => o.Name == fairPlayAuthorizationPolicyOptionName).FirstOrDefault();

            if (fariPlayAuthorizationPolicyOption == null)
            {
                fariPlayAuthorizationPolicyOption = await context.ContentKeyAuthorizationPolicyOptions.CreateAsync(
                    fairPlayAuthorizationPolicyOptionName,
                    ContentKeyDeliveryType.FairPlay,
                    restrictions,
                    JsonConvert.SerializeObject(fairPlayConfiguration));

                authorizationPolicy.Options.Add(fariPlayAuthorizationPolicyOption);
            }
            else
            {
                fariPlayAuthorizationPolicyOption.KeyDeliveryType = ContentKeyDeliveryType.FairPlay;
                fariPlayAuthorizationPolicyOption.Restrictions = restrictions;
                fariPlayAuthorizationPolicyOption.KeyDeliveryConfiguration = JsonConvert.SerializeObject(fairPlayConfiguration);

                await fariPlayAuthorizationPolicyOption.UpdateAsync();
            }

            // Asset Delivery Policy
            var commonEncryptionCbcsKey = await CreateCommonEncryptionCbcsContentKeyAsync(context);
            var acquisitionUri = await commonEncryptionCbcsKey.GetKeyDeliveryUrlAsync(ContentKeyDeliveryType.FairPlay);
            await commonEncryptionCbcsKey.DeleteAsync();

            var deliveryPolicyConfiguration = new Dictionary<AssetDeliveryPolicyConfigurationKey, string>
            {
                { AssetDeliveryPolicyConfigurationKey.FairPlayLicenseAcquisitionUrl, acquisitionUri.ToString().Replace("https://", "skd://") },
                { AssetDeliveryPolicyConfigurationKey.CommonEncryptionIVForCbcs, fairPlayConfiguration.ContentEncryptionIV }
            };

            var deliveryPolicyName = ConfigurationManager.AppSettings["DynamicCommonEncryptionCbcsDeliveryPolicyName"];
            var deliveryPolicy = context.AssetDeliveryPolicies.Where(p => p.Name == deliveryPolicyName).FirstOrDefault();

            if (deliveryPolicy == null)
            {
                deliveryPolicy = await context.AssetDeliveryPolicies.CreateAsync(
                    deliveryPolicyName,
                    AssetDeliveryPolicyType.DynamicCommonEncryptionCbcs,
                    AssetDeliveryProtocol.HLS,
                    deliveryPolicyConfiguration);
            }
            else
            {
                deliveryPolicy.AssetDeliveryPolicyType = AssetDeliveryPolicyType.DynamicCommonEncryptionCbcs;
                deliveryPolicy.AssetDeliveryProtocol = AssetDeliveryProtocol.HLS;
                deliveryPolicy.AssetDeliveryConfiguration = deliveryPolicyConfiguration;

                await deliveryPolicy.UpdateAsync();
            }
        }

        private static string GetJwtRequirements()
        {
            var primaryVerificationKey = ConfigurationManager.AppSettings["JWTRestrictionPrimaryVerificationKeyBase64"];
            var audience = ConfigurationManager.AppSettings["JWTRestrictionAudience"];
            var issuer = ConfigurationManager.AppSettings["JWTRestrictionIssuer"];

            var template = new TokenRestrictionTemplate(TokenType.JWT)
            {
                PrimaryVerificationKey = new SymmetricVerificationKey(Convert.FromBase64String(primaryVerificationKey)),
                Audience = audience,
                Issuer = issuer
            };

            return TokenRestrictionTemplateSerializer.Serialize(template);
        }

        private static async Task<IContentKey> CreateCommonEncryptionContentKeyAsync(MediaContextBase context)
        {
            var keyId = Guid.NewGuid();
            var contentKey = GetRandomBuffer(CommonEncryptionContentKeyLength);

            return await context.ContentKeys.CreateAsync(keyId, contentKey, CommonEncryptionContentKeyName, ContentKeyType.CommonEncryption);
        }

        private static async Task<IContentKey> CreateCommonEncryptionCbcsContentKeyAsync(MediaContextBase context)
        {
            var keyId = Guid.NewGuid();
            var contentKey = GetRandomBuffer(CommonEncryptionContentKeyLength);

            return await context.ContentKeys.CreateAsync(keyId, contentKey, CommonEncryptionCbcsContentKeyName, ContentKeyType.CommonEncryptionCbcs);
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

        private static string GetWidevineLicenseTemplateConfiguration()
        {
            var widevineLicenseTemplatePath = ConfigurationManager.AppSettings["WidevineLicenseTemplatePath"];

            return File.ReadAllText(widevineLicenseTemplatePath);
        }

        private static string GetPlayReadyLicenseTemplateConfiguration()
        {
            var playReadyLicenseTemplatePath = ConfigurationManager.AppSettings["PlayReadyLicenseTemplatePath"];

            return File.ReadAllText(playReadyLicenseTemplatePath);
        }

        private static async Task<FairPlayConfiguration> GetFairPlayConfigurationAsync(MediaContextBase context)
        {
            var previousAskKey = default(IContentKey);
            var askKeyId = Guid.NewGuid();
            var askKeyName = ConfigurationManager.AppSettings["FairPlayASKContentKeyName"];
            var askBytes = HexadecimalStringToByteArray(ConfigurationManager.AppSettings["FairPlayASKHexadecimal"]);
            var askKey = context.ContentKeys.Where(k => k.Name == askKeyName).FirstOrDefault();

            if (askKey == null)
            {
                askKey = await context.ContentKeys.CreateAsync(askKeyId, askBytes, askKeyName, ContentKeyType.FairPlayASk);
            }
            else
            {
                if (!askBytes.SequenceEqual(await askKey.GetClearKeyValueAsync()) || (askKey.ContentKeyType != ContentKeyType.FairPlayASk))
                {
                    previousAskKey = askKey;

                    askKey = await context.ContentKeys.CreateAsync(askKeyId, askBytes, askKeyName, ContentKeyType.FairPlayASk);
                }

                askKeyId = Guid.Parse(askKey.Id.Replace(ContentKeyPrefix, string.Empty));
            }

            var previousAppCertPasswordKey = default(IContentKey);
            var appCertPasswordKeyId = Guid.NewGuid();
            var appCertPasswordKeyName = ConfigurationManager.AppSettings["FairPlayAppCertPasswordContentKeyName"];
            var appCertPassword = ConfigurationManager.AppSettings["FairPlayAppCertPassword"];
            var appCertPasswordBytes = Encoding.UTF8.GetBytes(appCertPassword);
            var appCertPasswordKey = context.ContentKeys.Where(k => k.Name == appCertPasswordKeyName).FirstOrDefault();

            if (appCertPasswordKey == null)
            {
                appCertPasswordKey = await context.ContentKeys.CreateAsync(appCertPasswordKeyId, appCertPasswordBytes, appCertPasswordKeyName, ContentKeyType.FairPlayPfxPassword);
            }
            else
            {
                if (!appCertPasswordBytes.SequenceEqual(await appCertPasswordKey.GetClearKeyValueAsync()) || (appCertPasswordKey.ContentKeyType != ContentKeyType.FairPlayPfxPassword))
                {
                    previousAppCertPasswordKey = appCertPasswordKey;

                    appCertPasswordKey = await context.ContentKeys.CreateAsync(appCertPasswordKeyId, appCertPasswordBytes, appCertPasswordKeyName, ContentKeyType.FairPlayPfxPassword);
                }

                appCertPasswordKeyId = Guid.Parse(appCertPasswordKey.Id.Replace(ContentKeyPrefix, string.Empty));
            }

            var contentEncryptionIv = Guid.NewGuid().ToByteArray();
            var appCert = new X509Certificate2(ConfigurationManager.AppSettings["FairPlayAppCertPath"], appCertPassword, X509KeyStorageFlags.Exportable);
            var configuration = FairPlayConfiguration.CreateSerializedFairPlayOptionConfiguration(
                appCert,
                appCertPassword,
                appCertPasswordKeyId,
                askKeyId,
                contentEncryptionIv);

            if (previousAskKey != null)
            {
                await previousAskKey.DeleteAsync();
            }

            if (previousAppCertPasswordKey != null)
            {
                await previousAppCertPasswordKey.DeleteAsync();
            }

            return JsonConvert.DeserializeObject<FairPlayConfiguration>(configuration);
        }

        public static byte[] HexadecimalStringToByteArray(string hexadecimal)
        {
            return Enumerable.Range(0, hexadecimal.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hexadecimal.Substring(x, 2), 16))
                .ToArray();
        }
    }
}
