package io.adabox.auth.services;

import io.adabox.auth.repositories.UserRepository;
import io.adabox.auth.repositories.models.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;
    private final NonceService nonceService;

    @Autowired
    public UserDetailsServiceImpl(UserRepository userRepository, NonceService nonceService) {
        this.userRepository = userRepository;
        this.nonceService = nonceService;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String stakeKey) throws UsernameNotFoundException {
        User user = userRepository.findByStakeKey(stakeKey)
                .orElseThrow(() -> new UsernameNotFoundException("User Not Found with stakeKey: " + stakeKey));
        return UserDetailsImpl.build(user, nonceService.getIfPresent(stakeKey));
    }
}
