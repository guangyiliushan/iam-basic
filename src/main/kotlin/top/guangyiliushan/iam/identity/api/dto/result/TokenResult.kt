package top.guangyiliushan.iam.identity.api.dto.result

import com.fasterxml.jackson.annotation.JsonProperty

data class TokenResult(
    @field:JsonProperty("access_token")
    val accessToken: String,
    @field:JsonProperty("token_type")
    val tokenType: String = "Bearer",
    @field:JsonProperty("expires_in")
    val expiresIn: Long,
    @field:JsonProperty("refresh_token")
    val refreshToken: String? = null,
    @field:JsonProperty("id_token")
    val idToken: String? = null,
    val scope: String? = null
)
