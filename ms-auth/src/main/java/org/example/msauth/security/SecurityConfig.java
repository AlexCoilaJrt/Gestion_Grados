package org.example.msauth.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable() // Desactiva la protección CSRF (para APIs REST puede ser necesario)
                .authorizeRequests()
                .antMatchers("/auth/login", "/auth/register").permitAll() // Permitir acceso público a login y registro
                .antMatchers("/admin/**").hasRole("ADMIN") // Solo accesible para ADMIN
                .antMatchers("/dictaminador/**").hasRole("DICTAMINADOR") // Solo accesible para DICTAMINADOR
                .anyRequest().authenticated() // Cualquier otra ruta requiere autenticación
                .and()
                .formLogin(); // Utiliza autenticación basada en formularios con sesiones.
    }
}
