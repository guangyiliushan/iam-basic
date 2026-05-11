package top.guangyiliushan.iam.identity.internal.domain.model

data class Account(
    val id: Long?,
    val username: String,
    val password: String
) {
    init {
        require(id == null || id > 0)
        require(username.isNotBlank())
        require(password.isNotBlank())
    }
}
