package top.guangyiliushan.iam.identity.internal.infrastructure.persistence.repository

import org.springframework.stereotype.Repository
import top.guangyiliushan.iam.identity.internal.domain.model.Account
import top.guangyiliushan.iam.identity.internal.domain.repository.AccountRepository
import top.guangyiliushan.iam.identity.internal.infrastructure.persistence.jpa.AccountJpaRepository
import top.guangyiliushan.iam.identity.internal.infrastructure.persistence.mapper.AccountMapper

@Repository
class AccountRepositoryImpl(
    private val accountJpaRepository: AccountJpaRepository,
    private val accountMapper: AccountMapper = AccountMapper
) : AccountRepository {

    override fun save(account: Account): Account {
        val entity = accountMapper.toEntity(account)
        val savedEntity = accountJpaRepository.save(entity)
        return accountMapper.toDomain(savedEntity)
    }

    override fun findByUsername(username: String): Account? {
        val entity = accountJpaRepository.findByUsername(username)
        return entity?.let { accountMapper.toDomain(it) }
    }

    override fun existsByUsername(username: String): Boolean {
        return accountJpaRepository.findByUsername(username) != null
    }

    override fun deleteById(id: Long) {
        accountJpaRepository.deleteById(id)
    }
}
