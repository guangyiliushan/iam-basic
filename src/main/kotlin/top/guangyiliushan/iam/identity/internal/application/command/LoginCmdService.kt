package top.guangyiliushan.iam.identity.internal.application.command

import org.springframework.stereotype.Service
import top.guangyiliushan.iam.identity.api.IdentityErrorCode
import top.guangyiliushan.iam.identity.internal.application.assembler.LoginAssembler
import top.guangyiliushan.iam.identity.internal.domain.repository.AccountRepository
import top.guangyiliushan.iam.shared.BusinessException

@Service
class LoginCmdService(
    private val accountRepository: AccountRepository
) {
    fun login(username: String, password: String): Long {
        val account = accountRepository.findByUsername(username)
            ?: throw BusinessException(IdentityErrorCode.INVALID_CREDENTIALS)

        if (account.password != password) {
            throw BusinessException(IdentityErrorCode.INVALID_CREDENTIALS)
        }

        return LoginAssembler.toResult(account)
    }
}
