package basaball.score.security;

import io.jsonwebtoken.Jwts;
import java.io.IOException;
import java.util.ArrayList;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

public class JwtFilter extends BasicAuthenticationFilter {

  @Value("${SECRET}") 
  private String SECRET;
  
  @Value("${TOKEN_PREFIX}") 
  private String TOKEN_PREFIX;

  @Value("${HEADER_STRING") 
  private String HEADER_STRING;
  
  public JwtFilter(AuthenticationManager authenticationManager) {
    super(authenticationManager);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req,
                                  HttpServletResponse res,
                                  FilterChain chain) throws IOException, ServletException {
    String header = req.getHeader(HEADER_STRING);

    if (header == null || !header.startsWith(TOKEN_PREFIX)) {
      chain.doFilter(req, res);
      return;
    }

    UsernamePasswordAuthenticationToken authentication = getAuthentication(req);

    SecurityContextHolder.getContext().setAuthentication(authentication);
    chain.doFilter(req, res);
  }

  private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
    String token = request.getHeader(HEADER_STRING);
    if (token != null) {
      // parse the token.
      String teamId = Jwts.parser()
                          .setSigningKey(SECRET.getBytes())
                          .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                          .getBody()
                          .getSubject();

      if (teamId != null) {
        LoginTeam loginTeam = new LoginTeam();
        loginTeam.setId(Integer.parseInt(teamId));
        return new UsernamePasswordAuthenticationToken(loginTeam, null, new ArrayList<>());
      }
      return null;
    }
    return null;
  }
}