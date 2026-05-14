package top.guangyiliushan.iam.identity.api.dto.result

import com.fasterxml.jackson.annotation.JsonProperty

data class OpenIdConfigurationResult(
    val issuer: String,
    @field:JsonProperty("authorization_endpoint")
    val authorizationEndpoint: String,
    @field:JsonProperty("token_endpoint")
    val tokenEndpoint: String,
    @field:JsonProperty("userinfo_endpoint")
    val userinfoEndpoint: String,
    @field:JsonProperty("jwks_uri")
    val jwksUri: String,
    @field:JsonProperty("registration_endpoint")
    val registrationEndpoint: String? = null,
    @field:JsonProperty("scopes_supported")
    val scopesSupported: List<String> = emptyList(),
    @field:JsonProperty("response_types_supported")
    val responseTypesSupported: List<String> = emptyList(),
    @field:JsonProperty("response_modes_supported")
    val responseModesSupported: List<String> = emptyList(),
    @field:JsonProperty("grant_types_supported")
    val grantTypesSupported: List<String> = emptyList(),
    @field:JsonProperty("subject_types_supported")
    val subjectTypesSupported: List<String> = emptyList(),
    @field:JsonProperty("id_token_signing_alg_values_supported")
    val idTokenSigningAlgValuesSupported: List<String> = emptyList(),
    @field:JsonProperty("id_token_encryption_alg_values_supported")
    val idTokenEncryptionAlgValuesSupported: List<String> = emptyList(),
    @field:JsonProperty("id_token_encryption_enc_values_supported")
    val idTokenEncryptionEncValuesSupported: List<String> = emptyList(),
    @field:JsonProperty("userinfo_signing_alg_values_supported")
    val userinfoSigningAlgValuesSupported: List<String> = emptyList(),
    @field:JsonProperty("request_object_signing_alg_values_supported")
    val requestObjectSigningAlgValuesSupported: List<String> = emptyList(),
    @field:JsonProperty("token_endpoint_auth_methods_supported")
    val tokenEndpointAuthMethodsSupported: List<String> = emptyList(),
    @field:JsonProperty("token_endpoint_auth_signing_alg_values_supported")
    val tokenEndpointAuthSigningAlgValuesSupported: List<String> = emptyList(),
    @field:JsonProperty("claims_supported")
    val claimsSupported: List<String> = emptyList(),
    @field:JsonProperty("claim_types_supported")
    val claimTypesSupported: List<String> = emptyList(),
    @field:JsonProperty("claims_parameter_supported")
    val claimsParameterSupported: Boolean? = null,
    @field:JsonProperty("request_parameter_supported")
    val requestParameterSupported: Boolean? = null,
    @field:JsonProperty("request_uri_parameter_supported")
    val requestUriParameterSupported: Boolean? = null,
    @field:JsonProperty("require_request_uri_registration")
    val requireRequestUriRegistration: Boolean? = null,
    @field:JsonProperty("op_policy_uri")
    val opPolicyUri: String? = null,
    @field:JsonProperty("op_tos_uri")
    val opTosUri: String? = null,
    @field:JsonProperty("revocation_endpoint")
    val revocationEndpoint: String? = null,
    @field:JsonProperty("revocation_endpoint_auth_methods_supported")
    val revocationEndpointAuthMethodsSupported: List<String> = emptyList(),
    @field:JsonProperty("introspection_endpoint")
    val introspectionEndpoint: String? = null,
    @field:JsonProperty("introspection_endpoint_auth_methods_supported")
    val introspectionEndpointAuthMethodsSupported: List<String> = emptyList(),
    @field:JsonProperty("code_challenge_methods_supported")
    val codeChallengeMethodsSupported: List<String> = emptyList()
)
