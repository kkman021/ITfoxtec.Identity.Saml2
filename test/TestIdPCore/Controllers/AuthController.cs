using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using ITfoxtec.Identity.Saml2.Schemas.Metadata;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens.Saml2;
using Newtonsoft.Json;
using TestIdPCore.Models;
using HttpRequest = ITfoxtec.Identity.Saml2.Http.HttpRequest;
#if DEBUG
using System.Diagnostics;
#endif

namespace TestIdPCore.Controllers
{
    [AllowAnonymous]
    [Route("Auth")]
    public class AuthController : Controller
    {
        // List of Artifacts for test purposes.
        private static readonly ConcurrentDictionary<string, Saml2AuthnResponse> ArtifactSaml2AuthnResponseCache = new();
        private readonly Saml2Configuration _config;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly Settings _settings;

        public AuthController(Settings settings, Saml2Configuration config, IHttpClientFactory httpClientFactory)
        {
            _settings = settings;
            _config = config;
            _httpClientFactory = httpClientFactory;
        }

        [Route("Login")]
        public async Task<IActionResult> Login()
        {
            var requestBinding = new Saml2RedirectBinding();
            var saml2Request = ReadRelyingPartyFromLoginRequest(requestBinding);
            var relyingParty = ValidateRelyingParty(saml2Request).GetAwaiter().GetResult();

            var saml2AuthnRequest = new Saml2AuthnRequest(GetRpSaml2Configuration(relyingParty));
            requestBinding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnRequest);

            var session = new SamlDownSequenceData
            {
                Id = saml2AuthnRequest.Id.ToString(),
                RelayState = requestBinding.RelayState,
                Issuer = saml2Request,
                SessionId = HttpContext.Session.Id
            };

            HttpContext.Session.SetString("Saml2DowsSeq", JsonConvert.SerializeObject(session));

            return View(new LoginViewModel());
        }

        [Route("_Login")]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            var sessionData = JsonConvert.DeserializeObject<SamlDownSequenceData>(HttpContext.Session.GetString("Saml2DowsSeq"));
            var relyingParty = ValidateRelyingParty(sessionData.Issuer).GetAwaiter().GetResult();

            if (HttpContext.Session.Id == sessionData.SessionId)
            {
                var binding = new Saml2PostBinding
                {
                    RelayState = sessionData.RelayState
                };
                var config = GetRpSaml2Configuration(relyingParty);

                var authResponse = new Saml2AuthnResponse(config)
                {
                    InResponseTo = new Saml2Id(sessionData.Id),
                    Status = Saml2StatusCodes.Success,
                    Destination = relyingParty.AcsDestination,
                    SessionIndex = HttpContext.Session.Id
                };

                var claims = CreateTestUserClaims("ming.yang@advantech.com.tw");
                var claimsIdentity = new ClaimsIdentity(claims);
                authResponse.NameId = new Saml2NameIdentifier("ming.yang@advantech.com.tw", NameIdentifierFormats.Persistent);
                authResponse.ClaimsIdentity = claimsIdentity;
                authResponse.CreateSecurityToken(relyingParty.Issuer, subjectConfirmationLifetime: 5, issuedTokenLifetime: 60);

                return binding.Bind(authResponse).ToActionResult();
            }

            return BadRequest();
        }

        [Route("Artifact")]
        public async Task<IActionResult> Artifact()
        {
            try
            {
                var soapEnvelope = new Saml2SoapEnvelope();

                var httpRequest = await Request.ToGenericHttpRequestAsync(true);
                var relyingParty = await ValidateRelyingParty(ReadRelyingPartyFromSoapEnvelopeRequest(httpRequest, soapEnvelope));

                var saml2ArtifactResolve = new Saml2ArtifactResolve(GetRpSaml2Configuration(relyingParty));
                soapEnvelope.Unbind(httpRequest, saml2ArtifactResolve);

                if (!ArtifactSaml2AuthnResponseCache.Remove(saml2ArtifactResolve.Artifact, out var saml2AuthnResponse))
                {
                    throw new Exception($"Saml2AuthnResponse not found by Artifact '{saml2ArtifactResolve.Artifact}' in the cache.");
                }

                var saml2ArtifactResponse = new Saml2ArtifactResponse(_config, saml2AuthnResponse)
                {
                    InResponseTo = saml2ArtifactResolve.Id
                };
                soapEnvelope.Bind(saml2ArtifactResponse);
                return soapEnvelope.ToActionResult();
            }
            catch (Exception exc)
            {
#if DEBUG
                Debug.WriteLine($"SPSsoDescriptor error: {exc}");
#endif
                throw;
            }
        }

        [HttpPost("Logout")]
        public async Task<IActionResult> Logout()
        {
            var requestBinding = new Saml2PostBinding();
            var relyingParty = await ValidateRelyingParty(ReadRelyingPartyFromLogoutRequest(requestBinding));

            var saml2LogoutRequest = new Saml2LogoutRequest(GetRpSaml2Configuration(relyingParty));
            try
            {
                requestBinding.Unbind(Request.ToGenericHttpRequest(), saml2LogoutRequest);

                // **** Delete user session ****

                return LogoutResponse(saml2LogoutRequest.Id, Saml2StatusCodes.Success, requestBinding.RelayState, saml2LogoutRequest.SessionIndex, relyingParty);
            }
            catch (Exception exc)
            {
#if DEBUG
                Debug.WriteLine($"Saml 2.0 Logout Request error: {exc.ToString()}\nSaml Logout Request: '{saml2LogoutRequest.XmlDocument?.OuterXml}'");
#endif
                return LogoutResponse(saml2LogoutRequest.Id, Saml2StatusCodes.Responder, requestBinding.RelayState, saml2LogoutRequest.SessionIndex, relyingParty);
            }
        }

        private string ReadRelyingPartyFromLoginRequest<T>(Saml2Binding<T> binding)
        {
            return binding.ReadSamlRequest(Request.ToGenericHttpRequest(), new Saml2AuthnRequest(GetRpSaml2Configuration()))?.Issuer;
        }

        private string ReadRelyingPartyFromLogoutRequest<T>(Saml2Binding<T> binding)
        {
            return binding.ReadSamlRequest(Request.ToGenericHttpRequest(), new Saml2LogoutRequest(GetRpSaml2Configuration()))?.Issuer;
        }

        private string ReadRelyingPartyFromSoapEnvelopeRequest<T>(HttpRequest httpRequest, Saml2Binding<T> binding)
        {
            return binding.ReadSamlRequest(httpRequest, new Saml2ArtifactResolve(GetRpSaml2Configuration()))?.Issuer;
        }

        private IActionResult LoginResponse(Saml2Id inResponseTo, Saml2StatusCodes status, string relayState, RelyingParty relyingParty, string sessionIndex = null, IEnumerable<Claim> claims = null)
        {
            if (relyingParty.UseAcsArtifact)
            {
                return LoginArtifactResponse(inResponseTo, status, relayState, relyingParty, sessionIndex, claims);
            }

            return LoginPostResponse(inResponseTo, status, relayState, relyingParty, sessionIndex, claims);
        }

        private IActionResult LoginPostResponse(Saml2Id inResponseTo, Saml2StatusCodes status, string relayState, RelyingParty relyingParty, string sessionIndex = null,
            IEnumerable<Claim> claims = null)
        {
            var responsebinding = new Saml2PostBinding();
            responsebinding.RelayState = relayState;

            var saml2AuthnResponse = new Saml2AuthnResponse(GetRpSaml2Configuration(relyingParty))
            {
                InResponseTo = inResponseTo,
                Status = status,
                Destination = relyingParty.AcsDestination
            };
            if (status == Saml2StatusCodes.Success && claims != null)
            {
                saml2AuthnResponse.SessionIndex = sessionIndex;

                var claimsIdentity = new ClaimsIdentity(claims);
                saml2AuthnResponse.NameId =
                    new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single(), NameIdentifierFormats.Persistent);
                //saml2AuthnResponse.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single());
                saml2AuthnResponse.ClaimsIdentity = claimsIdentity;

                var token = saml2AuthnResponse.CreateSecurityToken(relyingParty.Issuer, subjectConfirmationLifetime: 5, issuedTokenLifetime: 60);
            }

            return responsebinding.Bind(saml2AuthnResponse).ToActionResult();
        }

        private IActionResult LoginArtifactResponse(Saml2Id inResponseTo, Saml2StatusCodes status, string relayState, RelyingParty relyingParty, string sessionIndex = null,
            IEnumerable<Claim> claims = null)
        {
            var responsebinding = new Saml2ArtifactBinding();
            responsebinding.RelayState = relayState;

            var saml2ArtifactResolve = new Saml2ArtifactResolve(GetRpSaml2Configuration(relyingParty))
            {
                Destination = relyingParty.AcsDestination
            };
            responsebinding.Bind(saml2ArtifactResolve);

            var saml2AuthnResponse = new Saml2AuthnResponse(GetRpSaml2Configuration(relyingParty))
            {
                InResponseTo = inResponseTo,
                Status = status
            };
            if (status == Saml2StatusCodes.Success && claims != null)
            {
                saml2AuthnResponse.SessionIndex = sessionIndex;

                var claimsIdentity = new ClaimsIdentity(claims);
                saml2AuthnResponse.NameId =
                    new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single(), NameIdentifierFormats.Persistent);
                //saml2AuthnResponse.NameId = new Saml2NameIdentifier(claimsIdentity.Claims.Where(c => c.Type == ClaimTypes.NameIdentifier).Select(c => c.Value).Single());
                saml2AuthnResponse.ClaimsIdentity = claimsIdentity;

                var token = saml2AuthnResponse.CreateSecurityToken(relyingParty.Issuer, subjectConfirmationLifetime: 5, issuedTokenLifetime: 60);
            }

            ArtifactSaml2AuthnResponseCache[saml2ArtifactResolve.Artifact] = saml2AuthnResponse;

            return responsebinding.ToActionResult();
        }

        private IActionResult LogoutResponse(Saml2Id inResponseTo, Saml2StatusCodes status, string relayState, string sessionIndex, RelyingParty relyingParty)
        {
            var responsebinding = new Saml2PostBinding();
            responsebinding.RelayState = relayState;

            var saml2LogoutResponse = new Saml2LogoutResponse(GetRpSaml2Configuration(relyingParty))
            {
                InResponseTo = inResponseTo,
                Status = status,
                Destination = relyingParty.SingleLogoutDestination,
                SessionIndex = sessionIndex
            };

            return responsebinding.Bind(saml2LogoutResponse).ToActionResult();
        }

        private Saml2Configuration GetRpSaml2Configuration(RelyingParty relyingParty = null)
        {
            var rpConfig = new Saml2Configuration
            {
                Issuer = _config.Issuer,
                SingleSignOnDestination = _config.SingleSignOnDestination,
                SingleLogoutDestination = _config.SingleLogoutDestination,
                ArtifactResolutionService = _config.ArtifactResolutionService,
                SigningCertificate = _config.SigningCertificate,
                SignatureAlgorithm = _config.SignatureAlgorithm,
                CertificateValidationMode = _config.CertificateValidationMode,
                RevocationMode = _config.RevocationMode,
                SignAuthnRequest = _config.SignAuthnRequest
            };

            rpConfig.AllowedAudienceUris.AddRange(_config.AllowedAudienceUris);

            if (relyingParty != null)
            {
                rpConfig.SignatureValidationCertificates.Add(relyingParty.SignatureValidationCertificate);
                rpConfig.EncryptionCertificate = relyingParty.EncryptionCertificate;
            }

            return rpConfig;
        }

        private async Task<RelyingParty> ValidateRelyingParty(string issuer)
        {
            using var cancellationTokenSource = new CancellationTokenSource(30 * 1000); // Cancel after 3 seconds.
            await Task.WhenAll(_settings.RelyingParties.Select(rp => LoadRelyingPartyAsync(rp, cancellationTokenSource)));

            return _settings.RelyingParties.Single(rp => rp.Issuer != null && rp.Issuer.Equals(issuer, StringComparison.InvariantCultureIgnoreCase));
        }

        private async Task LoadRelyingPartyAsync(RelyingParty rp, CancellationTokenSource cancellationTokenSource)
        {
            try
            {
                // Load RP if not already loaded.
                if (string.IsNullOrEmpty(rp.Issuer))
                {
                    var entityDescriptor = new EntityDescriptor();
                    await entityDescriptor.ReadSPSsoDescriptorFromUrlAsync(_httpClientFactory, new Uri(rp.Metadata), cancellationTokenSource.Token);
                    if (entityDescriptor.SPSsoDescriptor != null)
                    {
                        rp.Issuer = entityDescriptor.EntityId;
                        rp.AcsDestination = entityDescriptor.SPSsoDescriptor.AssertionConsumerServices.Where(a => a.IsDefault).OrderBy(a => a.Index).First().Location;
                        var singleLogoutService = entityDescriptor.SPSsoDescriptor.SingleLogoutServices.First();
                        rp.SingleLogoutDestination = singleLogoutService.ResponseLocation ?? singleLogoutService.Location;
                        rp.SignatureValidationCertificate = entityDescriptor.SPSsoDescriptor.SigningCertificates.First();
                    }
                    else
                    {
                        throw new Exception($"SPSsoDescriptor not loaded from metadata '{rp.Metadata}'.");
                    }
                }
            }
            catch (Exception exc)
            {
                //log error
#if DEBUG
                Debug.WriteLine($"SPSsoDescriptor error: {exc}");
#endif
            }
        }

        private IEnumerable<Claim> CreateTestUserClaims(string selectedNameID)
        {
            var userId = selectedNameID ?? "12345";
            yield return new Claim(ClaimTypes.NameIdentifier, userId);
            yield return new Claim(ClaimTypes.Upn, $"{userId}@email.test");
            yield return new Claim(ClaimTypes.Email, $"{userId}@someemail.test");
        }
    }
}