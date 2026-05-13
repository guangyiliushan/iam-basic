package top.guangyiliushan.iam.identity.internal.infrastructure.config

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties("iam.identity.cache.redis")
data class IdentityCacheProperties(
    val reuseMarkerTtlFloor: Duration = Duration.ofSeconds(1),
    val unlinkEnabled: Boolean = true
) {
    init {
        require(!reuseMarkerTtlFloor.isNegative && !reuseMarkerTtlFloor.isZero) {
            "iam.identity.cache.redis.reuse-marker-ttl-floor 必须大于 0"
        }
    }
}