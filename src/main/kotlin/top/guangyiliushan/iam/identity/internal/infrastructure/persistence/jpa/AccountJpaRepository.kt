package top.guangyiliushan.iam.identity.internal.infrastructure.persistence.jpa

import org.springframework.data.jpa.repository.JpaRepository
import top.guangyiliushan.iam.identity.internal.infrastructure.persistence.entity.AccountEntity

interface AccountJpaRepository : JpaRepository<AccountEntity, Long> {
    fun findByUsername(username: String): AccountEntity?
}
