package com.example.demo;

import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.HashSet;

@Transactional
@Service
public class SSUserDetailsService implements UserDetailsService {
    private UserRepository userRepository;

    @Autowired
    public SSUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username){
        try {
            User appUser = userRepository.findByUsername(username);

            if (appUser == null) {
                System.out.println("User not found with the provided username" + appUser.toString());
                return null;
            }
            System.out.println("User from username " + appUser.getUsername());
            return org.springframework.security.core.userdetails.User
                    .withUsername(appUser.getUsername())
                    .password(appUser.getPassword())
                    .roles(getAuthorities(appUser))
                    .build();

        } catch (Exception e) {
            throw new UsernameNotFoundException("User not found");
        }
    }

    private String[] getAuthorities(User appUser) {
        var authorities = new HashSet<String>();
        for (var role : appUser.getRoles()) {
            var grantedAuthority = new SimpleGrantedAuthority(role.getRole());
            authorities.add(grantedAuthority.getAuthority());
        }
        System.out.println("User authorities are " + authorities);
        return Arrays.copyOf(authorities.toArray(),authorities.size(), String[].class);
    }
}
