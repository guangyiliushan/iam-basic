package top.guangyiliushan.iam.identity.internal.domain.port.out

interface PasswordHashPort {
    fun hash(plainPassword: String): String?
    fun verify(plainPassword: String, hashedPassword: String): Boolean
}