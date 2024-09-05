package springOauth2.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Component
public class jwtAuthFilter extends OncePerRequestFilter {

    @Autowired
    public  Jwt jwtService;
    @Autowired
    public UserDetailsService userDetailsService;


    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain)  throws ServletException, IOException {

        String destination          = request.getRequestURI();
        List<String> public_pages   = Arrays.asList("/login", "/register", "/blog", "/about", "/team");
        boolean skip_auth           = public_pages.stream().anyMatch(destination::startsWith);
        if (skip_auth) {
            filterChain.doFilter(request, response);
            return;
        }


        String jwt              = null;
        String RefreshJwtToken_ = null;
        Cookie[] cookies = request.getCookies();

        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("JwtToken")) {
                    jwt = cookie.getValue();
                } else if (cookie.getName().equals("RefreshJwtToken")) {
                    RefreshJwtToken_ = cookie.getValue();
                }
                if (jwt != null && RefreshJwtToken_ != null) {
                    break;
                }
            }
        }

        String userEmail = null;
        if (jwt != null) {
            try {
                userEmail = jwtService.extractUsername(jwt);
            } catch (Exception e) {
                log.error("Invalid JWT: {}", e.getMessage());
            }
        }

        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(userEmail);
            if (userDetails != null && jwtService.isTokenValid(jwt, userDetails)) {
                //UsernamePasswordAuthenticationToken or Authentication
                Authentication authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                //authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        if (SecurityContextHolder.getContext().getAuthentication() == null && RefreshJwtToken_ != null  ) {
            UserDetails userDetails = jwtService.getUserDetailsFromJwt(RefreshJwtToken_);

            //--
            //String username          = jwtService.extractUsername(RefreshJwtToken_);
            //UserDetails userDetails_ = userDetailsService.loadUserByUsername(username);
            //--

            if (userDetails != null && jwtService.isRefreshTokenValid(RefreshJwtToken_, userDetails)) {
                //UsernamePasswordAuthenticationToken or Authentication
                Authentication authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                // authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
                String newJWT = jwtService.generateToken(userDetails);
                Cookie jwtCookie = new Cookie("JwtToken", newJWT);
                jwtCookie.setHttpOnly(true);
                jwtCookie.setSecure(true);          //  'Secure' flag for HTTPS-only transmission
                jwtCookie.setPath("/");
                response.addCookie(jwtCookie);
            }
        }
        filterChain.doFilter(request, response);


    }
}
