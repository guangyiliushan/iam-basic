package top.guangyiliushan.iam.identity.api.dto.result

import com.fasterxml.jackson.annotation.JsonProperty

data class IntrospectTokenResult(
    val active: Boolean,
    val scope: String? = null,
    @field:JsonProperty("client_id")
    val clientId: String? = null,
    val username: String? = null,
    @field:JsonProperty("token_type")
    val tokenType: String? = null,
    val exp: Long? = null,
    val iat: Long? = null,
    @field:JsonProperty("sub")
    val subject: String? = null,
    @field:JsonProperty("aud")
    val audience: String? = null,
    @field:JsonProperty("iss")
    val issuer: String? = null,
    @field:JsonProperty("jti")
    val tokenId: String? = null
)
