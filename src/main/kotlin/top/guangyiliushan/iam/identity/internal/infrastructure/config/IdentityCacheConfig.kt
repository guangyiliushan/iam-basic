package top.guangyiliushan.iam.identity.internal.infrastructure.config

import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.redis.core.script.DefaultRedisScript

@Configuration
@EnableConfigurationProperties(IdentityCacheProperties::class)
class IdentityCacheConfig {

    @Bean
    fun refreshTokenRotationScript(): DefaultRedisScript<String> = DefaultRedisScript<String>().apply {
        resultType = String::class.java
        setScriptText(
            """
            if redis.call('EXISTS', KEYS[1]) == 0 then return 'NOT_FOUND' end
            local currentId = redis.call('HGET', KEYS[1], 'currentTokenId')
            local currentHash = redis.call('HGET', KEYS[1], 'currentTokenHash')
            if not currentId or not currentHash then return 'REVOKED' end
            if currentId ~= ARGV[2] then
              if redis.call('EXISTS', KEYS[4]) == 1 then return 'REUSE_DETECTED' end
              return 'REVOKED'
            end
            if currentHash ~= ARGV[3] then return 'HASH_MISMATCH' end
            redis.call('HSET', KEYS[1], 'currentTokenId', ARGV[4], 'currentTokenHash', ARGV[5], 'currentRotation', ARGV[6], 'expiresAtEpochMilli', ARGV[8], 'updatedAtEpochMilli', ARGV[7])
            redis.call('EXPIRE', KEYS[1], ARGV[9])
            redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[9])
            redis.call('SET', KEYS[4], ARGV[1], 'EX', ARGV[10])
            redis.call('SET', KEYS[5], ARGV[1], 'EX', ARGV[9])
            redis.call('UNLINK', KEYS[2])
            return 'ROTATED'
            """.trimIndent()
        )
    }
}