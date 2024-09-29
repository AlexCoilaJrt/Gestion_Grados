package org.example.msauth.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/auth/login", "/auth/register").permitAll() // Permitir login y registro sin autenticación
                .antMatchers("/admin/**").hasRole("ADMIN") // Acceso para rol ADMIN
                .antMatchers("/dictaminador/**").hasRole("DICTAMINADOR") // Acceso para rol DICTAMINADOR
                .anyRequest().authenticated() // Otras rutas requieren autenticación
                .and()
                .formLogin(); // Usar autenticación de formulario
    }
}
