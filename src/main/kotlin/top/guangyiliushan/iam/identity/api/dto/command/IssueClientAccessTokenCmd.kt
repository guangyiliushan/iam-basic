package top.guangyiliushan.iam.identity.api.dto.command

data class IssueClientAccessTokenCmd(
    val clientId: String?,
    val clientSecret: String?
)
