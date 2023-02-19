package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import jakarta.transaction.Transactional;

import java.util.ArrayList;
import java.util.List;

@Transactional
@Service
public class SSUserDetailsService implements UserDetailsService {
    private UserRepository userRepository;

    @Autowired
    public SSUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        try {
            User appUser = userRepository.findByUsername(username);

            if (appUser == null) {
                System.out.println("User not found with the provided username" + appUser.toString());
                return null;
            }
            System.out.println("User from username " + appUser);
            return org.springframework.security.core.userdetails.User
                    .withUsername(appUser.getUsername())
                    .password(appUser.getPassword())
                    .roles(getAuthorities1(appUser))
                    .build();

        } catch (Exception e) {
            throw new UsernameNotFoundException("User not found");
        }
    }

    private String[] getAuthorities1(User appUser) {
        List<String> authorities = new ArrayList<>();
        for (Role role : appUser.getRoles()) {
            GrantedAuthority grantedAuthority = new SimpleGrantedAuthority(role.getRole());
            authorities.add(grantedAuthority.getAuthority());
        }
        System.out.println("User authorities are " + authorities);
        return authorities.toArray(new String[0]);
    }

    private String[] getAuthorities(User appUser) {
        List<String> roles = new ArrayList<>();
        for (Role role : appUser.getRoles()) {
            roles.add(role.getRole());
        }
        System.out.println("User authorities are " + roles);
        return roles.toArray(new String[0]);
    }
}
