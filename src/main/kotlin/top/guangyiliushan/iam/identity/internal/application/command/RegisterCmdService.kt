package top.guangyiliushan.iam.identity.internal.application.command

import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import top.guangyiliushan.iam.identity.api.IdentityErrorCode
import top.guangyiliushan.iam.identity.internal.application.assembler.RegisterAssembler
import top.guangyiliushan.iam.identity.internal.domain.repository.AccountRepository
import top.guangyiliushan.iam.shared.BusinessException

@Service
class RegisterCmdService(
    private val accountRepository: AccountRepository
) {
    @Transactional
    fun register(username: String, password: String): Long {
        if (accountRepository.existsByUsername(username)) {
            throw BusinessException(IdentityErrorCode.USERNAME_ALREADY_EXISTS)
        }
        val account = RegisterAssembler.toDomain(
            username, password,
            id = null
        )
        val savedAccount = accountRepository.save(account)

        return RegisterAssembler.toResult(savedAccount)
    }
}
