package top.guangyiliushan.iam.identity.api.dto.result

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty

@JsonInclude(JsonInclude.Include.NON_NULL)
data class OAuth2ErrorResult(
    val error: String,
    @field:JsonProperty("error_description")
    val errorDescription: String? = null
)
