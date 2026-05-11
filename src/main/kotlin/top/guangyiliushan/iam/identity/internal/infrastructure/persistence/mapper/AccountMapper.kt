package top.guangyiliushan.iam.identity.internal.infrastructure.persistence.mapper

import top.guangyiliushan.iam.identity.internal.domain.model.Account
import top.guangyiliushan.iam.identity.internal.infrastructure.persistence.entity.AccountEntity

object AccountMapper {

    fun toEntity(account: Account): AccountEntity {
        return AccountEntity().apply {
            this.id = account.id
            this.username = account.username
            this.password = account.password
        }
    }

    fun toDomain(entity: AccountEntity): Account {
        return Account(
            id = entity.id ?: throw IllegalStateException("Account ID cannot be null"),
            username = entity.username ?: throw IllegalStateException("Username cannot be null"),
            password = entity.password ?: throw IllegalStateException("Password cannot be null")
        )
    }

    fun toDomainList(entities: List<AccountEntity>): List<Account> {
        return entities.map { toDomain(it) }
    }
}
