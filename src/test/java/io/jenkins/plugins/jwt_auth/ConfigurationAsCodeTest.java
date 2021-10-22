package io.jenkins.plugins.jwt_auth;

import io.jenkins.plugins.casc.misc.ConfiguredWithCode;
import io.jenkins.plugins.casc.misc.JenkinsConfiguredWithCodeRule;
import org.junit.Rule;
import org.junit.Test;

import static org.junit.Assert.assertTrue;

public class ConfigurationAsCodeTest {

  @Rule public JenkinsConfiguredWithCodeRule r = new JenkinsConfiguredWithCodeRule();

  @Test
  @ConfiguredWithCode("configuration-as-code.yml")
  public void should_support_configuration_as_code() throws Exception {
    int hans = 3;
    //assertTrue( /* check plugin has been configured as expected */ );
  }
}
