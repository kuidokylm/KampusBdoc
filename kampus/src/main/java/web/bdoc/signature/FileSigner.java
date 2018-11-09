package web.bdoc.signature;

import org.digidoc4j.*;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Service
public class FileSigner {

    private static final Logger log = LoggerFactory.getLogger(FileSigner.class);
    private static final DigestAlgorithm DIGEST_ALGORITHM = DigestAlgorithm.SHA256;
    
    //private Configuration configuration = new Configuration(Configuration.Mode.TEST);
    //private Configuration configuration = new Configuration(Configuration.Mode.PROD);
    private Configuration configuration = Configuration.getInstance();
           
//    configuration.getTSL().refresh();

    public Container createContainer(DataFile dataFile) {
    	String serdiasukoht = "Koodikaru.crt";
    	Path path = Paths.get(serdiasukoht);
    	if (Files.exists(path)) // file exist 
    	{
    		String pswasukoht = "Koodikaru.psw";
    		path = Paths.get(pswasukoht);
        	if (Files.exists(path)) // file exist 
        	{
        	    try
        	    {
        	    	log.info("Seadistan OSCP sertifikaati "+serdiasukoht);
        	    	String salasona = new String ( Files.readAllBytes( path ) ).trim();    	    		
    	    		configuration.setOCSPAccessCertificateFileName(serdiasukoht);
    	    		configuration.setOCSPAccessCertificatePassword(salasona.toCharArray());    	  
    	    		configuration.setSignOCSPRequests(true);
        	    }
        	    catch (IOException e)
        	    {
        	    	log.info("OSCP sertifikaadi salasõna lugemise viga failist "+serdiasukoht);
        	    	log.error(e.getMessage());        	        
        	    }
    				
        	}
    	}
    	else
    	{
    		log.info("OSCP sertifikaadi faili ei ole "+serdiasukoht);
    	}
    	configuration.setTrustedTerritories("EE"); //võib OSCP pekki keerata
        Container container = BDocContainerBuilder.
                aContainer().
                withDataFile(dataFile).
                withConfiguration(configuration).
                build();
        return container;
    }

    public DataToSign getDataToSign(Container containerToSign, String certificateInHex) {
        X509Certificate certificate = getCertificate(certificateInHex);
        DataToSign dataToSign = SignatureBuilder.
                aSignature(containerToSign).
                withSigningCertificate(certificate).
                withSignatureDigestAlgorithm(DIGEST_ALGORITHM).
                //withSignatureProfile(SignatureProfile.LT_TM).  //BDOC                
                //withSignatureProfile(SignatureProfile.LT).  //asice
              //Note that BES signatures are missing OCSP (and Timestamp) and therefore are not valid as digital signatures by the law
                withSignatureProfile(SignatureProfile.B_BES). //PROD reshiimis ei tee OSCP päringut
                //withSignatureProfile(SignatureProfile.B_EPES).  //
                buildDataToSign();
        return dataToSign;
    }

    public void signContainer(Container container, DataToSign dataToSign, String signatureInHex) {
        byte[] signatureBytes = DatatypeConverter.parseHexBinary(signatureInHex);
        Signature signature = dataToSign.finalize(signatureBytes);
        container.addSignature(signature);
    }

    public void setConfiguration(Configuration configuration) {
        this.configuration = configuration;
    }

    private X509Certificate getCertificate(String certificateInHex) {
        byte[] certificateBytes = DatatypeConverter.parseHexBinary(certificateInHex);
        try (InputStream inStream = new ByteArrayInputStream(certificateBytes)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate)cf.generateCertificate(inStream);
            return certificate;
        } catch (CertificateException | IOException e) {
            log.error("Error reading certificate: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }
}