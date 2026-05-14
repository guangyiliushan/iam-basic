package top.guangyiliushan.iam.identity.internal.infrastructure.cache

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Repository
import top.guangyiliushan.iam.identity.internal.domain.port.out.JtiReplayProtectionPort
import top.guangyiliushan.iam.identity.internal.domain.model.TokenUse
import top.guangyiliushan.iam.identity.internal.infrastructure.config.IdentityCacheProperties

@Repository
class JtiReplayProtectionRepository(
    private val redisTemplate: StringRedisTemplate, private val cacheProperties: IdentityCacheProperties
) : JtiReplayProtectionPort {

    override fun registerIfAbsent(registration: JtiReplayProtectionPort.ReplayJtiRegistration): Boolean {
        val key = Keyspace.replayKey(registration.tokenUse, registration.tokenId)
        val value = listOf(
            registration.subject, registration.sessionId.orEmpty(), registration.expiresAt.toEpochMilli().toString()
        ).joinToString("|")
        return redisTemplate.opsForValue().setIfAbsent(key, value, registration.ttl()) == true
    }

    override fun exists(tokenId: String, tokenUse: TokenUse): Boolean =
        redisTemplate.hasKey(Keyspace.replayKey(tokenUse, tokenId)) == true

    override fun remove(tokenId: String, tokenUse: TokenUse): Boolean =
        unlink(Keyspace.replayKey(tokenUse, tokenId)) > 0

    private fun unlink(vararg keys: String): Long = redisTemplate.execute { connection ->
        val bytes = keys.map { it.toByteArray(Charsets.UTF_8) }.toTypedArray()
        val keyCommands = connection.keyCommands()
        if (cacheProperties.unlinkEnabled) keyCommands.unlink(*bytes) ?: 0 else keyCommands.del(*bytes) ?: 0
    } ?: 0
}