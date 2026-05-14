package top.guangyiliushan.iam.identity.internal.domain.port.out

import java.time.Duration
import java.time.Instant

interface RefreshTokenSessionCachePort {

    fun save(record: RefreshTokenSessionRecord): Boolean

    fun findByFamilyId(tokenFamilyId: String): RefreshTokenSessionRecord?

    fun findByTokenId(tokenId: String): RefreshTokenSessionRecord?

    fun findSessionIdsByAccountId(accountId: String, limit: Int = 100): List<String>

    fun rotate(command: RefreshTokenRotationCommand): RefreshTokenRotationResult

    fun revokeFamily(tokenFamilyId: String, revokedAt: Instant, reason: String): Boolean

    fun revokeSession(sessionId: String, revokedAt: Instant, reason: String): Long

    data class RefreshTokenSessionRecord(
        val accountId: String,
        val sessionId: String,
        val deviceId: String?,
        val tokenFamilyId: String,
        val currentTokenId: String,
        val currentTokenHash: String,
        val currentRotation: Long,
        val clientId: String,
        val issuedAt: Instant,
        val expiresAt: Instant,
        val updatedAt: Instant = issuedAt
    ) {
        fun ttl(now: Instant = updatedAt): Duration {
            val ttl = Duration.between(now, expiresAt)
            return if (ttl.isNegative || ttl.isZero) Duration.ofSeconds(1) else ttl
        }
    }

    data class RefreshTokenRotationCommand(
        val presentedTokenId: String,
        val presentedTokenHash: String,
        val tokenFamilyId: String,
        val nextTokenId: String,
        val nextTokenHash: String,
        val nextRotation: Long,
        val rotatedAt: Instant,
        val nextExpiresAt: Instant,
        val reuseDetectionWindow: Duration
    ) {
        fun nextRecordFrom(current: RefreshTokenSessionRecord): RefreshTokenSessionRecord =
            current.copy(
                currentTokenId = nextTokenId,
                currentTokenHash = nextTokenHash,
                currentRotation = nextRotation,
                expiresAt = nextExpiresAt,
                updatedAt = rotatedAt
            )
    }

    sealed interface RefreshTokenRotationResult {
        data class Rotated(
            val previousTokenId: String,
            val currentRecord: RefreshTokenSessionRecord
        ) : RefreshTokenRotationResult

        data class ReuseDetected(
            val tokenFamilyId: String,
            val reusedTokenId: String,
            val detectedAt: Instant
        ) : RefreshTokenRotationResult

        data class HashMismatch(
            val tokenFamilyId: String,
            val tokenId: String
        ) : RefreshTokenRotationResult

        data class Revoked(
            val tokenFamilyId: String
        ) : RefreshTokenRotationResult

        data class NotFound(
            val tokenFamilyId: String
        ) : RefreshTokenRotationResult
    }
}
