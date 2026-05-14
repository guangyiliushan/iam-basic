package top.guangyiliushan.iam.identity.api.dto.result

import com.fasterxml.jackson.annotation.JsonProperty

data class UserInfoResult(
    @field:JsonProperty("sub")
    val subject: String,
    val name: String? = null,
    @field:JsonProperty("given_name")
    val givenName: String? = null,
    @field:JsonProperty("family_name")
    val familyName: String? = null,
    val email: String? = null,
    @field:JsonProperty("email_verified")
    val emailVerified: Boolean? = null,
    val picture: String? = null,
    val locale: String? = null,
    @field:JsonProperty("updated_at")
    val updatedAt: Long? = null
)
