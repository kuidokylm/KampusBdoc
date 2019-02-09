package web.bdoc.configuration;

import java.util.HashMap;
import java.util.Map;

import org.digidoc4j.SignatureProfile;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

//https://www.baeldung.com/spring-boot-application-configuration

@Configuration
@Component
public class Customization implements
WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> {

  @Override
  public void customize(ConfigurableServletWebServerFactory container) {
      container.setPort(8083);
  }
}