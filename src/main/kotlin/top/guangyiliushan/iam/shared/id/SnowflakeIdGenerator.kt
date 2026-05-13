package top.guangyiliushan.iam.shared.id

interface SnowflakeIdGenerator {
    fun generate(): Long
}