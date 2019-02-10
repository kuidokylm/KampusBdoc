package web.bdoc;

import org.digidoc4j.Configuration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

//https://www.baeldung.com/spring-boot-app-as-a-service

//http://repo.jenkins-ci.org/releases/com/sun/winsw/winsw/2.1.2/
//Allatõmmatud exe nimeta ümber KampusBdoc.exe 
//käivita Administraatori õigustes KampusBdoc.exe install

//Seadistus.java klassis määrad ära, mis kinnitusteenust kasutad

/*
KampusBdoc.xml faili sisu 


<service>
<id>KampusBdoc</id>
<name>KampusBdoc</name>
<description>KAMPUS BDOC veebiteenus, Spring Boot as a Service.</description>
<env name="MYAPP_HOME" value="%BASE%"/>
<executable>java</executable>
<arguments>-Xmx512m -jar "%BASE%\bdoc-0.0.1-SNAPSHOT.jar"</arguments>
<logmode>rotate</logmode>
</service>

Paigaldamine: kataloogis, kus on bdoc-0.0.1-SNAPSHOT.jar fail

KampusBdoc.exe stop
KampusBdoc.exe uninstall
KampusBdoc.exe install
KampusBdoc.exe start

*/

@SpringBootApplication
public class KampusApplication {

	public static void main(String[] args) {
		
//		Configuration conf = Configuration.getInstance();
//		//Configuration conf = new Configuration(Configuration.Mode.PROD);
//		conf.setTrustedTerritories("EE"); 
//	    conf.getTSL().refresh();
		SpringApplication.run(KampusApplication.class, args);
	}
}
