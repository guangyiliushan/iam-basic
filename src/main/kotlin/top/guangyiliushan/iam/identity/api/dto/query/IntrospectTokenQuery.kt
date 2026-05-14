package top.guangyiliushan.iam.identity.api.dto.query

data class IntrospectTokenQuery(
    val token: String,
    val tokenTypeHint: String? = null
)
