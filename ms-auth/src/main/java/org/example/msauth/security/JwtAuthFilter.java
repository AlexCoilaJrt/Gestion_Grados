package org.example.msauth.security;

import org.example.msauth.service.impl.AuthUserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private AuthUserServiceImpl authUserService; // Asegúrate de usar el servicio correcto

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // 1. Obtener el token JWT desde la cabecera de la solicitud
        String jwtToken = getJwtFromRequest(request);

        try {
            // 2. Validar el token
            if (jwtToken != null && jwtProvider.validateToken(jwtToken)) {
                // 3. Obtener el nombre de usuario del token
                String username = jwtProvider.getUserNameFromJwt(jwtToken);

                // 4. Cargar detalles del usuario desde la base de datos
                UserDetails userDetails = authUserService.loadUserByUsername(username);

                // 5. Si el token es válido, establecer la autenticación
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Establecer la autenticación en el contexto de seguridad
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception e) {
            System.out.println("No se pudo establecer la autenticación: " + e.getMessage());
        }

        // Continuar con la cadena de filtros
        filterChain.doFilter(request, response);
    }

    // Método auxiliar para obtener el token JWT desde la cabecera "Authorization"
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);  // Remover "Bearer " para obtener solo el token
        }
        return null;
    }
}
