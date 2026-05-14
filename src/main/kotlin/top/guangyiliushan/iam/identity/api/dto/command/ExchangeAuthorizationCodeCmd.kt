package top.guangyiliushan.iam.identity.api.dto.command

data class ExchangeAuthorizationCodeCmd(
    val code: String,
    val redirectUri: String?,
    val clientId: String?,
    val clientSecret: String?
)
