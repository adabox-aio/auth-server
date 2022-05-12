package io.adabox.auth.services;

import io.adabox.auth.repositories.models.User;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@Setter
public class UserDetailsImpl implements UserDetails {

    private User user;
    private Collection<? extends GrantedAuthority> authorities;
    private String nonce;

    public UserDetailsImpl(User user, Collection<? extends GrantedAuthority> authorities, String nonce) {
        this.user = user;
        this.authorities = authorities;
        this.nonce = nonce;
    }
    public static UserDetailsImpl build(User user, String nonce) {
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());
        return new UserDetailsImpl(user, authorities, nonce);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return nonce;
    }

    @Override
    public String getUsername() {
        return user.getStakeKey();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !user.isBanned();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
