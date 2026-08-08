package com.inigo.AuthAndSecurity

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.context.properties.ConfigurationPropertiesScan
import org.springframework.boot.runApplication

@SpringBootApplication
@ConfigurationPropertiesScan
class AuthAndSecurityApplication

fun main(args: Array<String>) {
	runApplication<AuthAndSecurityApplication>(*args)
}