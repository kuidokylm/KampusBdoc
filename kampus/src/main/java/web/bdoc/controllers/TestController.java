package web.bdoc.controllers;


import org.digidoc4j.Configuration;
import org.digidoc4j.Version;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.web.bind.annotation.GetMapping;

import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import web.bdoc.configuration.Seadistus;


@RestController
public class TestController {
	
	private static final Logger log = LoggerFactory.getLogger(TestController.class);
	
	@Autowired
	Environment environment;
	
	@GetMapping(value= {"/","/default"})  // käivitamiseks kas http://localhost:8083 või http://localhost:8083/default
	public String vaikimisi(@RequestParam(value = "name", required = false, defaultValue = "KAMPUS BDOC Web Service 1.7") String[] Nimed) {
		log.info("KAMPUS BDOC Web Service töötamiseks Windows Servicena (/port - seadistuse info)");
        return Nimed[0];  
	}

	
	@GetMapping(value= {"/port"})
	public String port() {
		Configuration configuration = Configuration.getInstance();
		String port = environment.getProperty("local.server.port");
		String info = Seadistus.getSignatureProfileName();
		

		String versioon = org.digidoc4j.Version.VERSION;
		if ( versioon == null)
		{
			versioon="4.2.0";
		}
	
		info = "Port:"+port+" Seadistus:"+(configuration.isTest() ? "TEST" : "PROD")+" Profiil:"+info+" Digidoc4j: "+versioon;
		log.info(info);
		String ocsp = "OCSP: "+configuration.getOcspSource();
		log.info(ocsp);
		String tsp = "TSP: "+configuration.getTspSource();
		log.info(tsp);
        return info+" "+ocsp+" "+tsp; 
	}
	
	@GetMapping(value= {"/refreshtsl"})
	public String refreshtsl() {
		String vastus="ok"; 
		try
		{
			Configuration configuration = Configuration.getInstance();
			configuration.getTSL().refresh();
		}
		catch (Exception ex)
		{
			vastus=ex.getMessage();
			log.error("refreshtsl Error: "+vastus);
		}
        return vastus; 
	}
		
}
