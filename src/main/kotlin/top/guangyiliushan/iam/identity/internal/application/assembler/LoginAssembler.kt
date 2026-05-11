package top.guangyiliushan.iam.identity.internal.application.assembler

import top.guangyiliushan.iam.identity.internal.domain.model.Account

object LoginAssembler {
    fun toResult(account: Account): Long {
        return requireNotNull(account.id)
    }
}
