package com.inigo.AuthAndSecurity

import org.junit.jupiter.api.Test
import org.springframework.boot.test.context.SpringBootTest

// Dummy credentials keep the context loading without GOOGLE_CLIENT_ID /
// GOOGLE_CLIENT_SECRET being set in the environment.
@SpringBootTest(
	properties = [
		"spring.security.oauth2.client.registration.google.client-id=test-client-id",
		"spring.security.oauth2.client.registration.google.client-secret=test-client-secret",
	]
)
class AuthAndSecurityApplicationTests {

	@Test
	fun contextLoads() {
	}

}