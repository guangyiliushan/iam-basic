package top.guangyiliushan.iam.identity.internal.application.assembler

import top.guangyiliushan.iam.identity.internal.domain.model.Account

object RegisterAssembler {

    fun toDomain(username : String, password : String, id: Long?): Account {
        return Account(
            id = id,
            username = username,
            password = password
        )
    }

    fun toResult(account: Account): Long {
        return requireNotNull(account.id)
    }
}
