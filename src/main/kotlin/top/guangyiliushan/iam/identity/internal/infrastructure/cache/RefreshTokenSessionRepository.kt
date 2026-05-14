package top.guangyiliushan.iam.identity.internal.infrastructure.cache

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.data.redis.core.script.DefaultRedisScript
import org.springframework.stereotype.Repository
import top.guangyiliushan.iam.identity.internal.domain.port.out.RefreshTokenSessionCachePort
import top.guangyiliushan.iam.identity.internal.infrastructure.config.IdentityCacheProperties
import top.guangyiliushan.iam.identity.internal.infrastructure.config.IdentityJwtProperties
import java.time.Duration
import java.time.Instant

@Repository
class RefreshTokenSessionRepository(
    private val redisTemplate: StringRedisTemplate,
    private val cacheProperties: IdentityCacheProperties,
    private val jwtProperties: IdentityJwtProperties,
    private val refreshTokenRotationScript: DefaultRedisScript<String>
) : RefreshTokenSessionCachePort {

    override fun save(record: RefreshTokenSessionCachePort.RefreshTokenSessionRecord): Boolean {
        val ttl = record.ttl()
        val familyKey = Keyspace.refreshFamilyKey(record.tokenFamilyId)
        redisTemplate.opsForHash<String, String>().putAll(familyKey, toHash(record))
        redisTemplate.expire(familyKey, ttl)
        redisTemplate.opsForValue()
            .set(Keyspace.refreshTokenIndexKey(record.currentTokenId), record.tokenFamilyId, ttl)
        redisTemplate.opsForValue()
            .set(Keyspace.refreshSessionKey(record.sessionId), record.tokenFamilyId, ttl)
        val accountSessionsKey = Keyspace.refreshAccountSessionsKey(record.accountId)
        redisTemplate.opsForZSet().add(accountSessionsKey, record.sessionId, record.issuedAt.toEpochMilli().toDouble())
        redisTemplate.expire(accountSessionsKey, ttl)
        purgeStaleAccountSessions(record.accountId)
        enforceConcurrentSessionLimit(record.accountId, record.sessionId)
        return true
    }

    override fun findByFamilyId(tokenFamilyId: String): RefreshTokenSessionCachePort.RefreshTokenSessionRecord? {
        val values = redisTemplate.opsForHash<String, String>().entries(Keyspace.refreshFamilyKey(tokenFamilyId))
        return if (values.isEmpty()) null else toRecord(values)
    }

    override fun findByTokenId(tokenId: String): RefreshTokenSessionCachePort.RefreshTokenSessionRecord? =
        redisTemplate.opsForValue().get(Keyspace.refreshTokenIndexKey(tokenId))?.let(::findByFamilyId)

    override fun findSessionIdsByAccountId(accountId: String, limit: Int): List<String> {
        purgeStaleAccountSessions(accountId)
        return redisTemplate.opsForZSet()
            .reverseRange(Keyspace.refreshAccountSessionsKey(accountId), 0, (limit - 1).toLong())
            ?.toList()
            ?: emptyList()
    }

    override fun rotate(command: RefreshTokenSessionCachePort.RefreshTokenRotationCommand): RefreshTokenSessionCachePort.RefreshTokenRotationResult {
        val current = findByFamilyId(command.tokenFamilyId)
            ?: return RefreshTokenSessionCachePort.RefreshTokenRotationResult.NotFound(command.tokenFamilyId)
        val ttl = ttlSeconds(command.nextExpiresAt, command.rotatedAt)
        val reuseTtl = maxOf(cacheProperties.reuseMarkerTtlFloor, command.reuseDetectionWindow).seconds
        val result = redisTemplate.execute(
            refreshTokenRotationScript,
            listOf(
                Keyspace.refreshFamilyKey(command.tokenFamilyId),
                Keyspace.refreshTokenIndexKey(command.presentedTokenId),
                Keyspace.refreshTokenIndexKey(command.nextTokenId),
                Keyspace.refreshReuseKey(command.presentedTokenId),
                Keyspace.refreshSessionKey(current.sessionId)
            ),
            command.tokenFamilyId,
            command.presentedTokenId,
            command.presentedTokenHash,
            command.nextTokenId,
            command.nextTokenHash,
            command.nextRotation.toString(),
            command.rotatedAt.toEpochMilli().toString(),
            command.nextExpiresAt.toEpochMilli().toString(),
            ttl.toString(),
            reuseTtl.toString()
        ) ?: "NOT_FOUND"
        return when (result) {
            "ROTATED" -> findByFamilyId(command.tokenFamilyId)?.let {
                touchAccountSessionsKey(it.accountId, it.ttl())
                RefreshTokenSessionCachePort.RefreshTokenRotationResult.Rotated(command.presentedTokenId, it)
            } ?: RefreshTokenSessionCachePort.RefreshTokenRotationResult.NotFound(command.tokenFamilyId)

            "REUSE_DETECTED" -> RefreshTokenSessionCachePort.RefreshTokenRotationResult.ReuseDetected(
                command.tokenFamilyId, command.presentedTokenId, command.rotatedAt
            )

            "HASH_MISMATCH" -> RefreshTokenSessionCachePort.RefreshTokenRotationResult.HashMismatch(
                command.tokenFamilyId, command.presentedTokenId
            )

            "REVOKED" -> RefreshTokenSessionCachePort.RefreshTokenRotationResult.Revoked(command.tokenFamilyId)
            else -> RefreshTokenSessionCachePort.RefreshTokenRotationResult.NotFound(command.tokenFamilyId)
        }
    }

    override fun revokeFamily(tokenFamilyId: String, revokedAt: Instant, reason: String): Boolean {
        val record = findByFamilyId(tokenFamilyId) ?: return false
        redisTemplate.opsForZSet().remove(Keyspace.refreshAccountSessionsKey(record.accountId), record.sessionId)
        cleanEmptyAccountSessionsKey(record.accountId)
        return unlink(
            Keyspace.refreshFamilyKey(tokenFamilyId),
            Keyspace.refreshTokenIndexKey(record.currentTokenId),
            Keyspace.refreshSessionKey(record.sessionId)
        ) > 0
    }

    override fun revokeSession(sessionId: String, revokedAt: Instant, reason: String): Long {
        val familyId = redisTemplate.opsForValue().get(Keyspace.refreshSessionKey(sessionId)) ?: return 0
        return if (revokeFamily(familyId, revokedAt, reason)) 1 else 0
    }

    private fun toHash(record: RefreshTokenSessionCachePort.RefreshTokenSessionRecord): Map<String, String> = mapOf(
        "accountId" to record.accountId,
        "sessionId" to record.sessionId,
        "deviceId" to (record.deviceId ?: ""),
        "tokenFamilyId" to record.tokenFamilyId,
        "currentTokenId" to record.currentTokenId,
        "currentTokenHash" to record.currentTokenHash,
        "currentRotation" to record.currentRotation.toString(),
        "clientId" to record.clientId,
        "issuedAtEpochMilli" to record.issuedAt.toEpochMilli().toString(),
        "expiresAtEpochMilli" to record.expiresAt.toEpochMilli().toString(),
        "updatedAtEpochMilli" to record.updatedAt.toEpochMilli().toString()
    )

    private fun toRecord(values: Map<String, String>) = RefreshTokenSessionCachePort.RefreshTokenSessionRecord(
        accountId = values.getValue("accountId"),
        sessionId = values.getValue("sessionId"),
        deviceId = values["deviceId"]?.ifBlank { null },
        tokenFamilyId = values.getValue("tokenFamilyId"),
        currentTokenId = values.getValue("currentTokenId"),
        currentTokenHash = values.getValue("currentTokenHash"),
        currentRotation = values.getValue("currentRotation").toLong(),
        clientId = values.getValue("clientId"),
        issuedAt = Instant.ofEpochMilli(values.getValue("issuedAtEpochMilli").toLong()),
        expiresAt = Instant.ofEpochMilli(values.getValue("expiresAtEpochMilli").toLong()),
        updatedAt = Instant.ofEpochMilli(values.getValue("updatedAtEpochMilli").toLong())
    )

    private fun ttlSeconds(expiresAt: Instant, now: Instant): Long = maxOf(1, Duration.between(now, expiresAt).seconds)

    private fun enforceConcurrentSessionLimit(accountId: String, currentSessionId: String) {
        val overflow = findOverflowSessionIds(accountId, currentSessionId)
        if (overflow.isEmpty()) {
            return
        }
        val revokedAt = Instant.now()
        overflow.forEach { revokeSession(it, revokedAt, "concurrent_session_limit_exceeded") }
    }

    private fun findOverflowSessionIds(accountId: String, currentSessionId: String): List<String> {
        val accountSessionsKey = Keyspace.refreshAccountSessionsKey(accountId)
        val allSessionIds = redisTemplate.opsForZSet()
            .range(accountSessionsKey, 0, -1)
            ?.toList()
            ?: emptyList()
        val overflow = allSessionIds.size - jwtProperties.session.maxConcurrentSessions
        if (overflow <= 0) {
            return emptyList()
        }
        return allSessionIds
            .filter { it != currentSessionId }
            .take(overflow)
    }

    private fun purgeStaleAccountSessions(accountId: String) {
        val accountSessionsKey = Keyspace.refreshAccountSessionsKey(accountId)
        val sessionIds = redisTemplate.opsForZSet().range(accountSessionsKey, 0, -1) ?: return
        val staleSessionIds = sessionIds.filter { redisTemplate.hasKey(Keyspace.refreshSessionKey(it)) != true }
        if (staleSessionIds.isNotEmpty()) {
            redisTemplate.opsForZSet().remove(accountSessionsKey, *staleSessionIds.toTypedArray())
        }
        cleanEmptyAccountSessionsKey(accountId)
    }

    private fun touchAccountSessionsKey(accountId: String, ttl: Duration) {
        redisTemplate.expire(Keyspace.refreshAccountSessionsKey(accountId), ttl)
    }

    private fun cleanEmptyAccountSessionsKey(accountId: String) {
        val accountSessionsKey = Keyspace.refreshAccountSessionsKey(accountId)
        if ((redisTemplate.opsForZSet().zCard(accountSessionsKey) ?: 0) == 0L) {
            unlink(accountSessionsKey)
        }
    }

    private fun unlink(vararg keys: String): Long = redisTemplate.execute { c ->
        val bytes = keys.filter { it.isNotBlank() }.map { it.toByteArray(Charsets.UTF_8) }.toTypedArray()
        val commands = c.keyCommands(); if (cacheProperties.unlinkEnabled) commands.unlink(*bytes)
        ?: 0 else commands.del(*bytes) ?: 0
    } ?: 0
}
