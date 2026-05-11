package top.guangyiliushan.iam.identity.api.dto.command

data class LoginCmd (
    val username: String,
    val password: String
)