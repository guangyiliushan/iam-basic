package top.guangyiliushan.iam.shared

import org.springframework.context.annotation.Configuration
import org.springframework.http.MediaType
import org.springframework.web.servlet.config.annotation.ApiVersionConfigurer
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer


@Configuration
class ApiConfig : WebMvcConfigurer {

    override fun configureApiVersioning(configurer: ApiVersionConfigurer) {
        configurer
            .addSupportedVersions("1.0")
            .setDefaultVersion("1.0")
            .useRequestHeader("X-API-Version")
            .useQueryParam("version")
            .useMediaTypeParameter(MediaType.APPLICATION_JSON, "version")
    }
}