package web.bdoc.controllers;


import org.digidoc4j.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class TestController {
	
	private static final Logger log = LoggerFactory.getLogger(TestController.class);
	
	@Autowired
	Environment environment;
	
	@GetMapping(value= {"/","/default"})  // käivitamiseks kas http://localhost:8083 või http://localhost:8083/default
	public String vaikimisi(@RequestParam(value = "name", required = false, defaultValue = "KAMPUS BDOC Web Service") String[] Nimed) {
		log.info("KAMPUS BDOC Web Service");
        return Nimed[0];  
	}

	
	@GetMapping(value= {"/port"})
	public String port() {
		Configuration configuration = Configuration.getInstance();
		String port = environment.getProperty("local.server.port");
		String info = "Port:"+port+" Seadistus:"+(configuration.isTest() ? "TEST" : "PROD");
		log.info(info);
        return info; 
	}
	
}
