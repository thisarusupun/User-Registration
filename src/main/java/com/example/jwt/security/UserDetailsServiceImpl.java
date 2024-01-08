package com.example.jwt.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.example.jwt.entity.User;
import com.example.jwt.repository.UserRepository;

@Service
public class UserDetailsServiceImpl implements UserDetailsService{

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException{
        User user= userRepository.findByUsername(username).orElse(null);

        if (user == null){
            throw new UsernameNotFoundException("User Not Found With The Given Username");
        }

        return org.springframework.security.core.userdetails.User.builder()
            .username(user.getUsername())
            .password(user.getPassword())
            .build();
    }
    
}
