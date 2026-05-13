package top.guangyiliushan.iam.identity.internal.domain.model

enum class TokenUse(
    val claimValue: String,
    val redisSegment: String
) {
    ACCESS(claimValue = "access", redisSegment = "at"),
    REFRESH(claimValue = "refresh", redisSegment = "rt");

    companion object {
        fun fromClaimValue(value: String?): TokenUse? =
            value?.trim()?.takeIf { it.isNotEmpty() }?.let { claim ->
                entries.firstOrNull { it.claimValue == claim }
            }
    }
}