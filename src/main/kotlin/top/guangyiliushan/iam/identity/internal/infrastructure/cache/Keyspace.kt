package top.guangyiliushan.iam.identity.internal.infrastructure.cache

import top.guangyiliushan.iam.identity.internal.domain.model.TokenUse

object Keyspace {
    private const val ROOT = "iam:idn"
    const val MONITORING_PATTERN = "$ROOT:*"

    fun replayKey(tokenUse: TokenUse, tokenId: String): String =
        "$ROOT:jwt:${tokenUse.redisSegment}:jti:$tokenId"

    fun refreshFamilyKey(tokenFamilyId: String): String =
        "$ROOT:jwt:rt:family:$tokenFamilyId"

    fun refreshTokenIndexKey(tokenId: String): String =
        "$ROOT:jwt:rt:idx:$tokenId"

    fun refreshReuseKey(tokenId: String): String =
        "$ROOT:jwt:rt:reuse:$tokenId"

    fun refreshSessionKey(sessionId: String): String =
        "$ROOT:jwt:rt:session:$sessionId"
}