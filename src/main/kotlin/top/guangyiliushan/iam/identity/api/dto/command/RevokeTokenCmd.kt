package top.guangyiliushan.iam.identity.api.dto.command

data class RevokeTokenCmd(
    val token: String,
    val tokenTypeHint: String? = null
)
