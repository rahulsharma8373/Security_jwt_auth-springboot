package com.rahul.venturing.user;

import static com.rahul.venturing.user.Permission.ADMIN_CREATE;
import static com.rahul.venturing.user.Permission.ADMIN_READ;
import static com.rahul.venturing.user.Permission.MEMBER_CREATE;
import static com.rahul.venturing.user.Permission.MEMBER_READ;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public enum Role {
	ADMIN(Set.of(ADMIN_READ, ADMIN_CREATE, MEMBER_READ, MEMBER_CREATE)), MEMBER(Set.of(MEMBER_READ, MEMBER_CREATE));

	@Getter
	private final Set<Permission> permissions;

	public List<SimpleGrantedAuthority> getAuthorities() {
		var authorities = getPermissions().stream()
				.map(authority -> new SimpleGrantedAuthority(authority.getPermission())).collect(Collectors.toList());
		authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
		return authorities;
	}
}
