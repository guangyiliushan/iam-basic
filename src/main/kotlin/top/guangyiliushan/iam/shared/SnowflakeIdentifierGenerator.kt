package top.guangyiliushan.iam.shared

import org.hibernate.engine.spi.SharedSessionContractImplementor
import org.hibernate.id.IdentifierGenerator
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.io.Serializable
import java.time.Instant

@Component
class SnowflakeIdentifierGenerator : IdentifierGenerator {

    companion object {
        private const val START_TIMESTAMP = 1704067200000L // 2024-01-01 00:00:00
        private const val WORKER_ID_BITS = 5L
        private const val DATACENTER_ID_BITS = 5L
        private const val SEQUENCE_BITS = 12L

        private const val MAX_WORKER_ID = (1L shl WORKER_ID_BITS.toInt()) - 1 // 31
        private const val MAX_DATACENTER_ID = (1L shl DATACENTER_ID_BITS.toInt()) - 1 // 31
        private const val MAX_SEQUENCE = (1L shl SEQUENCE_BITS.toInt()) - 1 // 4095

        private const val WORKER_ID_SHIFT = SEQUENCE_BITS
        private const val DATACENTER_ID_SHIFT = SEQUENCE_BITS + WORKER_ID_BITS
        private const val TIMESTAMP_LEFT_SHIFT = SEQUENCE_BITS + WORKER_ID_BITS + DATACENTER_ID_BITS
    }

    @Value("\${snowflake.worker-id:1}")
    private var workerId: Long = 1

    @Value("\${snowflake.datacenter-id:1}")
    private var datacenterId: Long = 1

    private var sequence = 0L
    private var lastTimestamp = -1L

    override fun generate(session: SharedSessionContractImplementor, obj: Any?): Serializable {
        return nextId()
    }

    @Synchronized
    fun nextId(): Long {
        if (workerId !in 0..MAX_WORKER_ID) {
            throw IllegalArgumentException("snowflake.worker-id must be in range [0, $MAX_WORKER_ID], actual=$workerId")
        }
        if (datacenterId !in 0..MAX_DATACENTER_ID) {
            throw IllegalArgumentException("snowflake.datacenter-id must be in range [0, $MAX_DATACENTER_ID], actual=$datacenterId")
        }

        var timestamp = getCurrentTimestamp()

        if (timestamp < lastTimestamp) {
            throw RuntimeException("时钟回拨异常，拒绝生成ID，持续 ${lastTimestamp - timestamp}ms")
        }

        if (timestamp == lastTimestamp) {
            sequence = (sequence + 1) and MAX_SEQUENCE
            if (sequence == 0L) {
                timestamp = tilNextMillis(lastTimestamp)
            }
        } else {
            sequence = 0L
        }

        lastTimestamp = timestamp

        return ((timestamp - START_TIMESTAMP).shl(TIMESTAMP_LEFT_SHIFT.toInt())) or
                (datacenterId.shl(DATACENTER_ID_SHIFT.toInt())) or
                (workerId.shl(WORKER_ID_SHIFT.toInt())) or
                sequence
    }

    private fun tilNextMillis(lastTimestamp: Long): Long {
        var timestamp = getCurrentTimestamp()
        while (timestamp <= lastTimestamp) {
            timestamp = getCurrentTimestamp()
        }
        return timestamp
    }

    private fun getCurrentTimestamp(): Long {
        return Instant.now().toEpochMilli()
    }
}