package org.vdisk.oauth2.demo;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.util.StringUtils;
import org.vdisk.oauth2.demo.oidc.ExcludeClientCredentialsClientRegistrationRepository;

/**
 * @author vdisk <vdisk@foxmail.com>
 * @version 1.0
 * @date 2021-06-15 17:04
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableConfigurationProperties({OAuth2ClientProperties.class, OAuth2ResourceServerProperties.class})
@Configuration
public class OidcWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    private final InMemoryClientRegistrationRepository clientRegistrationRepository;

    private final OAuth2ResourceServerProperties oauth2ResourceServerProperties;

    public OidcWebSecurityConfigurerAdapter(
            InMemoryClientRegistrationRepository clientRegistrationRepository,
            OAuth2ResourceServerProperties oauth2ResourceServerProperties) {
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.oauth2ResourceServerProperties = oauth2ResourceServerProperties;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.authorizeRequests(requests -> requests.anyRequest().authenticated());
        http.oauth2Login(configure ->
                configure.clientRegistrationRepository(
                        new ExcludeClientCredentialsClientRegistrationRepository(
                                this.clientRegistrationRepository)));
        http.oauth2Client();
        http.logout(configure -> {
            OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(
                    this.clientRegistrationRepository);
            logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
            configure.logoutSuccessHandler(logoutSuccessHandler);
        });
        // make jwt optional
        String jwtIssuerUri = this.oauth2ResourceServerProperties.getJwt().getIssuerUri();
        if (StringUtils.hasText(jwtIssuerUri)) {
            http.oauth2ResourceServer().jwt();
        }
    }
}
