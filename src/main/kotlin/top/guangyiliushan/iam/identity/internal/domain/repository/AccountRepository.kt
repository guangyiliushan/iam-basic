package top.guangyiliushan.iam.identity.internal.domain.repository

import top.guangyiliushan.iam.identity.internal.domain.model.Account

interface AccountRepository {
    fun save(account: Account): Account
    fun findByUsername(username: String): Account?
    fun existsByUsername(username: String): Boolean
    fun deleteById(id: Long)
}
