package springOauth2.config;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import springOauth2.entity.User;
import springOauth2.repository.UserRepository;

import java.util.Optional;

@AllArgsConstructor
@Configuration
@EnableWebSecurity
public class security {

    @Autowired
    UserRepository userRepository;

    @Autowired
    public jwtAuthFilter jwtAuthFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .cors(cors -> cors.disable())
            .authorizeHttpRequests(requests -> requests
                .requestMatchers("/permitted").authenticated()
                .anyRequest().permitAll()
            )
            .oauth2Login(oauth2 -> oauth2
                //.loginPage("/login")
                .defaultSuccessUrl("/", true)
                .failureUrl("/login?error=true")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(
                        oAuth2UserService()
                    )
                )
            )
            .addFilterBefore(jwtAuthFilter,UsernamePasswordAuthenticationFilter.class)

        ;
        return http.build();
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {

//        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
//        return request -> {
//            OAuth2User oauth2User = delegate.loadUser(request);
//            return oauth2User;
//        };

        DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();
        return request -> {
            OAuth2User oauth2User   = defaultOAuth2UserService.loadUser(request);
            String googleId         = oauth2User.getAttribute("sub");
            String name             = oauth2User.getAttribute("name");
            String email            = oauth2User.getAttribute("email");
            String pictureUrl       = oauth2User.getAttribute("picture");
            Optional<User> user = userRepository.findByGoogleId(googleId);
            if (user.isEmpty()) {
                User newUser = new User();
                newUser.setGoogleId(googleId);
                newUser.setName(name);
                newUser.setEmail(email);
                newUser.setPictureUrl(pictureUrl);
                userRepository.save(newUser);
            }
            return oauth2User;
        };
    }
}
