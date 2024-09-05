package springOauth2.controller;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.ui.Model;
import springOauth2.config.Jwt;
import springOauth2.entity.User;

import java.io.IOException;

@Controller
public class route {

    @Autowired
    public Jwt jwtService;

    @GetMapping("/")
    public String home(Model model, HttpServletResponse response) {

        String jwtToken=null;
        String refreshToken=null;

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            OAuth2User oAuth2User = oauthToken.getPrincipal();
            //  OIDC (OpenID Connect)
            if (oAuth2User instanceof OidcUser) {
                OidcUser oidcUser       = (OidcUser) oAuth2User;
                String fullName         = oidcUser.getFullName();
                String email            = oidcUser.getEmail();
                String picture          = oidcUser.getPicture();

                var user = User.builder().name(fullName).email(email).enabled(true).build();
                jwtToken      = jwtService.generateToken(user);
                refreshToken  = jwtService.generateRefreshToken(user);

            }
            //  OAuth2 (non-OpenID Connect)
            else if (oAuth2User instanceof DefaultOAuth2User) {
                DefaultOAuth2User defaultOAuth2User = (DefaultOAuth2User) oAuth2User;
                String name                         = defaultOAuth2User.getAttribute("name");
                String email                        = defaultOAuth2User.getAttribute("email");
                String picture                      = defaultOAuth2User.getAttribute("picture");

                var user = User.builder().name(name).email(email).enabled(true).build();
                jwtToken      = jwtService.generateToken(user);
                refreshToken  = jwtService.generateRefreshToken(user);
            }
        } else {
            System.out.println("User is not authenticated.");
            return "redirect:/login";
        }

        Cookie jwtCookie = new Cookie("JWT-TOKEN", jwtToken);
        jwtCookie.setHttpOnly(true);
        jwtCookie.setPath("/");

        Cookie refreshCookie = new Cookie("REFRESH-TOKEN", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setPath("/");

        response.addCookie(jwtCookie);
        response.addCookie(refreshCookie);

        try {
            response.sendRedirect("http://localhost:3000/dashboard");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return null;
    }

    @GetMapping("/signup")
    public String signup() {
            return "signup";  // Returns the signup page (optional)
        }

}
