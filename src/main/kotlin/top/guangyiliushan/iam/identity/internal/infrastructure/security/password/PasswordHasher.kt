package top.guangyiliushan.iam.identity.internal.infrastructure.security.password

import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Component
import top.guangyiliushan.iam.identity.internal.domain.port.out.PasswordHashPort

@Component
class PasswordHasher(
    private val passwordEncoder: PasswordEncoder
) : PasswordHashPort {
    /**
     * 对明文密码进行哈希处理。
     * Salt 和算法参数会自动生成并嵌入到返回的字符串中。
     */
    override fun hash(plainPassword: String): String? {
        return passwordEncoder.encode(plainPassword)
    }
    /**
     * 验证一个明文密码是否与存储的哈希字符串匹配。
     * 验证时会自动从哈希字符串中解析出盐和算法参数。
     */
    override fun verify(plainPassword: String, hashedPassword: String): Boolean {
        return passwordEncoder.matches(plainPassword, hashedPassword)
    }
}
