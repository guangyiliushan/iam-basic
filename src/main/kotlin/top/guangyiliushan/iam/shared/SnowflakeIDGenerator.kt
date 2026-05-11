package top.guangyiliushan.iam.shared

import org.hibernate.annotations.IdGeneratorType

@IdGeneratorType(SnowflakeIdentifierGenerator::class)
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.FIELD, AnnotationTarget.PROPERTY_GETTER)
annotation class SnowflakeIDGenerator