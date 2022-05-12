package io.adabox.auth.controllers.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.adabox.auth.repositories.models.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class JwtResponse {

    private String jwt;
    private User user;

    @JsonIgnore
    private List<String> roles;
    private boolean isNew;
}
