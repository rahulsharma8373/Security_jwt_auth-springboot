package com.rahul.venturing.config;

import static com.rahul.venturing.user.Permission.ADMIN_CREATE;
import static com.rahul.venturing.user.Permission.ADMIN_READ;
import static com.rahul.venturing.user.Permission.MEMBER_CREATE;
import static com.rahul.venturing.user.Permission.MEMBER_READ;
import static com.rahul.venturing.user.Role.ADMIN;
import static com.rahul.venturing.user.Role.MEMBER;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {

	private final AuthenticationProvider authenticationProvider;
	private final JwtAuthFilter jwtAuthFilter;


	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		return http.csrf(AbstractHttpConfigurer::disable)
				.authorizeHttpRequests(req -> req.requestMatchers("/venture/v1/auth/*").permitAll()
						.requestMatchers("/venture/v1/management/**").hasAnyRole(ADMIN.name(), MEMBER.name())
						.requestMatchers(GET, "/venture/v1/management/**")
						.hasAnyAuthority(ADMIN_READ.name(), MEMBER_READ.name())
						.requestMatchers(POST, "/venture/v1/management/**")
						.hasAnyAuthority(ADMIN_CREATE.name(), MEMBER_CREATE.name()).anyRequest().authenticated())
				.sessionManagement(session -> session.sessionCreationPolicy(STATELESS))
				.authenticationProvider(authenticationProvider)
				.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class).build();
	}

}
