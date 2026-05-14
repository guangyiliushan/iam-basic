package top.guangyiliushan.iam.identity.api.dto.query

data class AuthorizeQuery(
    val responseType: String,
    val clientId: String,
    val redirectUri: String? = null,
    val scope: String? = null,
    val state: String? = null,
    val nonce: String? = null
)
