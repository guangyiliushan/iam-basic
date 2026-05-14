package top.guangyiliushan.iam.identity.api.dto.result

data class JwkSetResult(
    val keys: List<JwkResult>
) {
    data class JwkResult(
        val kty: String,
        val use: String? = null,
        val kid: String,
        val alg: String? = null,
        val n: String? = null,
        val e: String? = null,
        val crv: String? = null,
        val x: String? = null,
        val y: String? = null
    )
}
