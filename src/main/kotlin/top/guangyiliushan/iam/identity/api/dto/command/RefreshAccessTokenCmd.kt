package top.guangyiliushan.iam.identity.api.dto.command

data class RefreshAccessTokenCmd(
    val refreshToken: String,
    val clientId: String?,
    val clientSecret: String?
)
