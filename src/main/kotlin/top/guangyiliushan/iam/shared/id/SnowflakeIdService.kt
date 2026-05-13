package top.guangyiliushan.iam.shared.id

import jakarta.annotation.PostConstruct
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component

@Component
class SnowflakeIdService : SnowflakeIdGenerator {

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
        private const val MAX_CLOCK_BACKWARD_MS = 5L
    }

    private val logger = LoggerFactory.getLogger(SnowflakeIdService::class.java)

    @Value($$"${snowflake.worker-id:1}")
    private var workerId: Long = 1

    @Value($$"${snowflake.datacenter-id:1}")
    private var datacenterId: Long = 1

    private var sequence = 0L
    private var lastTimestamp = -1L

    @Volatile
    private var initialized = false

    @PostConstruct
    fun initialize() {
        validateConfiguration()
        initialized = true
        logger.info("Snowflake ID generator initialized: workerId={}, datacenterId={}, startTimestamp={}", workerId, datacenterId, START_TIMESTAMP)
    }

    @Synchronized
    override fun generate(): Long {
        return try {
            nextId()
        } catch (ex: SnowflakeGenerationException) {
            throw ex
        } catch (ex: Exception) {
            throw SnowflakeGenerationException("雪花ID生成失败", ex)
        }
    }

    private fun nextId(): Long {
        ensureInitialized()
        var timestamp = currentTimestamp()

        if (timestamp < lastTimestamp) {
            val offset = lastTimestamp - timestamp
            if (offset <= MAX_CLOCK_BACKWARD_MS) {
                logger.warn("Snowflake clock moved backwards by {}ms, waiting until {}", offset, lastTimestamp)
                timestamp = waitUntil(lastTimestamp)
            } else {
                throw SnowflakeGenerationException("时钟回拨异常，拒绝生成ID: ${offset}ms")
            }
        }

        if (timestamp == lastTimestamp) {
            sequence = (sequence + 1) and MAX_SEQUENCE
            if (sequence == 0L) {
                timestamp = waitUntil(lastTimestamp)
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

    private fun ensureInitialized() {
        if (!initialized) {
            validateConfiguration()
            initialized = true
            logger.info("Snowflake ID generator lazily initialized: workerId={}, datacenterId={}", workerId, datacenterId)
        }
    }

    private fun validateConfiguration() {
        require(workerId in 0..MAX_WORKER_ID) { "snowflake.worker-id must be in range [0, $MAX_WORKER_ID], actual=$workerId" }
        require(datacenterId in 0..MAX_DATACENTER_ID) { "snowflake.datacenter-id must be in range [0, $MAX_DATACENTER_ID], actual=$datacenterId" }
    }

    private fun waitUntil(lastTimestamp: Long): Long {
        var timestamp = currentTimestamp()
        while (timestamp <= lastTimestamp) {
            Thread.onSpinWait()
            timestamp = currentTimestamp()
        }
        return timestamp
    }

    private fun currentTimestamp(): Long = System.currentTimeMillis()
}