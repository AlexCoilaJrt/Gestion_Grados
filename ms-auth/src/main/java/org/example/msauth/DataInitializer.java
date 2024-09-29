package org.example.msauth;

import org.example.msauth.entity.Role;
import org.example.msauth.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private RoleRepository roleRepository;

    @Override
    public void run(String... args) throws Exception {
        // Crear roles solo si no existen
        if (roleRepository.findByName("ROLE_USER").isEmpty()) {
            roleRepository.save(new Role(null, "ROLE_USER"));
        }

        if (roleRepository.findByName("ROLE_ADMIN").isEmpty()) {
            roleRepository.save(new Role(null, "ROLE_ADMIN"));
        }

        if (roleRepository.findByName("ROLE_DICTAMINADOR").isEmpty()) {
            roleRepository.save(new Role(null, "ROLE_DICTAMINADOR"));  // Nuevo Rol
        }
    }
}
