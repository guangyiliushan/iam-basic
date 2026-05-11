package top.guangyiliushan.iam.identity.internal.infrastructure.persistence.entity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import top.guangyiliushan.iam.shared.SnowflakeIDGenerator

@Entity
@Table(name = "account")
class AccountEntity {
    @Id
    @SnowflakeIDGenerator
    @Column(name = "id")
    var id: Long? = null

    @Column(name = "username")
    var username: String ?= null

    @Column(name = "password")
    var password: String ?= null
}
