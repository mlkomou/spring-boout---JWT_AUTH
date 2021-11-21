package com.music.app.service;

import com.music.app.entity.ApplicationUser;
import com.music.app.entity.UserConnected;
import com.music.app.repo.ApplicationUserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

import static com.music.app.constants.SecurityConstants.EXPIRATION_TIME;
import static com.music.app.constants.SecurityConstants.KEY;

@Service
@AllArgsConstructor
public class AuthService {
    private final ApplicationUserRepository applicationUserRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final AuthenticationManager authenticationManager;



    public ResponseEntity<UserConnected> loginUser(ApplicationUser applicationUser) {

        try {
            ApplicationUser user = applicationUserRepository.findByUsername(applicationUser.getUsername());
            UserConnected userConnected = new UserConnected();

            if (user != null) {

                Authentication authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(applicationUser.getUsername(), applicationUser.getPassword()));
                System.out.println("user present " + user.getUsername());
                Date exp = new Date(System.currentTimeMillis() + EXPIRATION_TIME);
                Key key = Keys.hmacShaKeyFor(KEY.getBytes());
                Claims claims = Jwts.claims().setSubject(((User) authentication.getPrincipal()).getUsername());
                String token = Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.HS512, key).setExpiration(exp).compact();
                userConnected.setToken(token);
                userConnected.setUsername(applicationUser.getUsername());
                System.out.println("user connected " + userConnected.getUsername());
                return new ResponseEntity<>(userConnected, HttpStatus.OK);
            }
            return new ResponseEntity<>(new UserConnected(), HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception e) {
            return new ResponseEntity<>(new UserConnected(), HttpStatus.INTERNAL_SERVER_ERROR);
        }


    }
}
