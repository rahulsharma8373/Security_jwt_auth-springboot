package com.rahul.venturing.auth;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.rahul.venturing.config.JwtService;
import com.rahul.venturing.repository.UserRepository;
import com.rahul.venturing.user.User;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthService {
	private final UserRepository userRepository;
	private final JwtService jwtService;
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;

	public AuthenticationResponse register(RegisterRequest registerRequest) {
		var user = User.builder()
				.firstName(registerRequest.getFirstName())
				.lastName(registerRequest.getLastName())
				.email(registerRequest.getEmail())
				.password(passwordEncoder.encode(registerRequest.getPassword()))
				.role(registerRequest.getRole()).build();
		var savedUser = userRepository.save(user);
		String jwtToken = jwtService.generateToken(user);
		return AuthenticationResponse.builder().accessToken(jwtToken).build();
	}

	public AuthenticationResponse authenticate(AuthenticationRequest request) {
		
		authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
		var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
		String jwtToken = jwtService.generateToken(user);
		return AuthenticationResponse.builder().accessToken(jwtToken).build();

	}
}
