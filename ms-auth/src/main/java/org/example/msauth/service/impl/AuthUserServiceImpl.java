package org.example.msauth.service.impl;

import org.example.msauth.dto.AuthUserDto;
import org.example.msauth.entity.AuthUser;
import org.example.msauth.entity.Role;
import org.example.msauth.entity.TokenDto;
import org.example.msauth.repository.AuthUserRepository;
import org.example.msauth.repository.RoleRepository;
import org.example.msauth.security.JwtProvider;
import org.example.msauth.service.AuthUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthUserServiceImpl implements AuthUserService, UserDetailsService {

    @Autowired
    private AuthUserRepository authUserRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtProvider jwtProvider;

    // Implementación del método save
    @Override
    public AuthUser save(AuthUserDto authUserDto) {
        Optional<AuthUser> user = authUserRepository.findByUserName(authUserDto.getUserName());
        if (user.isPresent()) {
            throw new RuntimeException("User already exists");
        }
        String password = passwordEncoder.encode(authUserDto.getPassword());
        AuthUser authUser = AuthUser.builder()
                .userName(authUserDto.getUserName())
                .password(password)
                .build();

        // Asignar roles al usuario
        Role dictaminadorRole = roleRepository.findByName("ROLE_DICTAMINADOR")
                .orElseThrow(() -> new RuntimeException("Role not found"));
        authUser.setRoles(Set.of(dictaminadorRole));  // Asignar solo el rol de Dictaminador

        return authUserRepository.save(authUser);
    }

    // Implementación del método login
    @Override
    public TokenDto login(AuthUserDto authUserDto) {
        Optional<AuthUser> user = authUserRepository.findByUserName(authUserDto.getUserName());
        if (!user.isPresent()) {
            throw new UsernameNotFoundException("User not found");
        }

        if (passwordEncoder.matches(authUserDto.getPassword(), user.get().getPassword())) {
            // Si las credenciales son correctas, generar el token
            return new TokenDto(jwtProvider.createToken(user.get()));
        } else {
            throw new RuntimeException("Invalid credentials");
        }
    }

    // Implementación del método validate
    @Override
    public TokenDto validate(String token) {
        if (!jwtProvider.validateToken(token)) {
            throw new RuntimeException("Invalid token");
        }

        String username = jwtProvider.getUserNameFromJwt(token);
        if (!authUserRepository.findByUserName(username).isPresent()) {
            throw new UsernameNotFoundException("User not found");
        }

        return new TokenDto(token);
    }

    // Implementación de UserDetailsService para Spring Security
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUser user = authUserRepository.findByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

        // Convertir AuthUser a UserDetails de Spring Security
        return new org.springframework.security.core.userdetails.User(
                user.getUserName(),
                user.getPassword(),
                user.getRoles().stream()
                        .map(role -> new org.springframework.security.core.authority.SimpleGrantedAuthority(role.getName()))
                        .collect(Collectors.toList())
        );
    }
}
