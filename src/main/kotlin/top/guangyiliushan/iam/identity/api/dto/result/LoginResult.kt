package top.guangyiliushan.iam.identity.api.dto.result

data class LoginResult(
    val userId: Long,
    val accessToken: String,
    val tokenType: String = "Bearer",
    val accessTokenExpiresIn: Long
)
