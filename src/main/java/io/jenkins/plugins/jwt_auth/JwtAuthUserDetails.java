/**
 *
 */
package io.jenkins.plugins.jwt_auth;

import java.util.Collection;
import javax.annotation.Nonnull;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

public class JwtAuthUserDetails extends User implements UserDetails {

    private static final long serialVersionUID = 1L;

    public JwtAuthUserDetails(@Nonnull String login, @Nonnull Collection<GrantedAuthority> authorities) {
        super(login, "", true, true, true, true, authorities);
    }
}
