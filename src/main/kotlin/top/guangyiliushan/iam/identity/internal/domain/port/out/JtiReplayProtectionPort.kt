package top.guangyiliushan.iam.identity.internal.domain.port.out

import top.guangyiliushan.iam.identity.internal.domain.model.TokenUse
import java.time.Duration
import java.time.Instant

interface JtiReplayProtectionPort {

    fun registerIfAbsent(registration: ReplayJtiRegistration): Boolean

    fun exists(tokenId: String, tokenUse: TokenUse): Boolean

    fun remove(tokenId: String, tokenUse: TokenUse): Boolean

    data class ReplayJtiRegistration(
        val tokenId: String,
        val tokenUse: TokenUse,
        val subject: String,
        val sessionId: String? = null,
        val expiresAt: Instant,
        val ttlBuffer: Duration = Duration.ZERO,
        val recordedAt: Instant = Instant.now()
    ) {
        fun ttl(now: Instant = recordedAt): Duration {
            val ttl = Duration.between(now, expiresAt).plus(ttlBuffer)
            return if (ttl.isNegative || ttl.isZero) Duration.ofSeconds(1) else ttl
        }
    }
}