package web.bdoc.controllers;
//koopia DigiDoc4j Hwcrypto Demo
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import web.bdoc.configuration.Seadistus;
import web.bdoc.model.Digest;
import web.bdoc.model.Failid;
import web.bdoc.model.Signatuur;
import web.bdoc.model.Signatuurid;
import web.bdoc.model.Valideerimine;
import web.bdoc.signature.FileSigner;
import java.security.cert.X509Certificate;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Configuration;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureProfile;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.asice.bdoc.BDocContainerBuilder;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.xml.bind.DatatypeConverter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

//serialiseerimine ja deserialiseerimine
//https://www.tutorialspoint.com/java/java_serialization.htm
//https://github.com/open-eid/digidoc4j/wiki/Examples-of-using-it#simple-external-signing-example-eg-signing-in-web

@RestController
public class SigningController {

    private static final Logger log = LoggerFactory.getLogger(SigningController.class);
    @Autowired
    private FileSigner signer;

    
    @RequestMapping(value="/multiuploadsforhash", method= RequestMethod.POST)
    public Digest handleUploadHash(@RequestParam MultipartFile[] failid
    		, @RequestParam String certInHex) {
    	Digest digest = new Digest();
    	digest.setResult(Digest.ERROR_GENERATING_HASH);
    	String ff=Arrays.stream(failid).map( e -> e.getOriginalFilename() ).collect( Collectors.joining(",") );
    	
        log.info("Töötlen ülesse laetud faile räsi jaoks "+ff);
        try {
            byte[] fileBytes = failid[0].getBytes();
            String fileName = failid[0].getOriginalFilename();
            String mimeType = failid[0].getContentType();
            DataFile dataFile = new DataFile(fileBytes, fileName, mimeType);
            log.info("Loon ülesse laetud failide jaoks konteineri");
            Container container = signer.createContainer(dataFile);
            
            for(int i=1;i<failid.length;i++)
            {
            	fileBytes = failid[i].getBytes();
                fileName = failid[i].getOriginalFilename();
                mimeType = failid[i].getContentType();
                dataFile = new DataFile(fileBytes, fileName, mimeType);
                container.addDataFile(dataFile);
            }
                        
            //serialiseerime konteineri
            byte[] containerdata = SerializationUtils.serialize(container);
            digest.setContainer(containerdata);
            
            DataToSign dataToSign = signer.getDataToSign(container, certInHex);            
            log.info("dataToSign profile "+dataToSign.getConfiguration().getSignatureProfile().name());
            
            //serialiseerime            
            byte[] data = SerializationUtils.serialize(dataToSign);            
            digest.setDataToSign(data);
            log.info("Genereerin konteineri räsi");
            String dataToSignInHex =
                    DatatypeConverter.printHexBinary(DSSUtils.digest(DigestAlgorithm.SHA256, dataToSign.getDataToSign()));
            digest.setHex(dataToSignInHex); 
            digest.setResult(Digest.OK);
        } catch (IOException e) {
            log.error("Error Viga üleslaetud failides " + ff+" "+e.getMessage(), e);
            digest.setResult("Error Viga üleslaetud failides " + ff+" "+e.getMessage());
        }
        return digest;
    }
    
    
    @RequestMapping(value="/uploadforhash", method= RequestMethod.POST)
    public Digest handleUploadHash(@RequestParam MultipartFile file
    		, @RequestParam String certInHex) {
    	Digest digest = new Digest();
    	digest.setResult(Digest.ERROR_GENERATING_HASH);
        log.info("Töötlen ülesse laetud faili räsi jaoks"+file.getOriginalFilename());
        try {
            byte[] fileBytes = file.getBytes();
            String fileName = file.getOriginalFilename();
            String mimeType = file.getContentType();
            DataFile dataFile = new DataFile(fileBytes, fileName, mimeType);
            log.info("Loon ülesse laetud faili jaoks konteineri");
            Container container = signer.createContainer(dataFile);            
                        
            //serialiseerime konteineri
            byte[] containerdata = SerializationUtils.serialize(container);
            digest.setContainer(containerdata);
            
            DataToSign dataToSign = signer.getDataToSign(container, certInHex);
            log.info("uploadforhash dataToSign profile "+dataToSign.getConfiguration().getSignatureProfile().name());
            //serialiseerime            
            byte[] data = SerializationUtils.serialize(dataToSign);            
            digest.setDataToSign(data);
            log.info("Genereerin konteineri räsi");
            String dataToSignInHex =
                    DatatypeConverter.printHexBinary(DSSUtils.digest(DigestAlgorithm.SHA256, dataToSign.getDataToSign()));
            digest.setHex(dataToSignInHex); 
            digest.setResult(Digest.OK);
        } catch (IOException e) {
            log.error("Error Viga üleslaetud failis " + file.getOriginalFilename()+" "+e.getMessage(), e);
            digest.setResult("Error Viga üleslaetud failis " + file.getOriginalFilename()+" "+e.getMessage());
        }
        return digest;
    }

    @RequestMapping(value="/createContainer", method = RequestMethod.POST)
    public Digest createContainer(@RequestParam String signatureInHex
    		, @RequestParam MultipartFile file, @RequestParam MultipartFile dfile) {
    	Digest digest = new Digest();
    	digest.setResult(Digest.ERROR_SIGNING);
        log.info("Loon konteinerit signatuuri jaoks " + StringUtils.left(signatureInHex, 30) + "...");
        log.info("DataToSign " + dfile.getOriginalFilename());
        log.info("Konteiner " + file.getOriginalFilename());    
        try
        {
	        //deserialiseerime konteineri	        
	        byte[] fileBytes = file.getBytes();	        
	        Container container = (Container) SerializationUtils.deserialize(fileBytes);
	        
	        //deserialiseerime datatosign 	        
	        fileBytes = dfile.getBytes();	        
	        DataToSign dataToSign = (DataToSign) SerializationUtils.deserialize(fileBytes);                       
	        log.info("createContainer dataToSign profiil "+dataToSign.getConfiguration().getSignatureProfile().name());  
	        
	        //lisame konteinerile signatuuri
	        log.info("Lisan konteinerile signatuuri");  
            signer.signContainer(container, dataToSign, signatureInHex);
            InputStream containerStream = container.saveAsStream();
            byte[] containerdata = IOUtils.toByteArray(containerStream);
            
            //byte[] containerdata = SerializationUtils.serialize(container);
            digest.setContainer(containerdata);
            //digest.setDataToSign(SerializationUtils.serialize(container));
            digest.setResult(Digest.OK);
            digest.setHex("application/vnd.etsi.asic-e+zip"); //BDOC(ASICE)
            return digest;
        } catch (Exception e) {
            log.error("Error Signing document "+e.getMessage(), e);
            digest.setResult("Error Signing document "+e.getMessage());
        }
        return digest;
    }

    
    @RequestMapping(value="/getContainerSignatures", method = RequestMethod.POST)
    public Signatuurid getContainerSignatures(@RequestParam MultipartFile file) {
    	Signatuurid signad = new Signatuurid();
    	signad.setResult(Digest.ERROR_GETTING_SIGNATURES);
        log.info("Konteineri signatuurid " + file.getOriginalFilename());    
        try
        {
	        //loome konteineri	        
	        byte[] fileBytes = file.getBytes();	        
	        InputStream inputStream = new ByteArrayInputStream(fileBytes);
	        Container container = ContainerBuilder.
	        	    aContainer(Container.DocumentType.ASICE).  
	        	    fromStream(inputStream).
	        	    build();
	        log.info("Konteineri signatuure kokku " + container.getSignatures().size());  
	        ArrayList<Signatuur> signatuurid = new ArrayList<Signatuur>();
	        boolean korras=true;
	        for (Signature sig : container.getSignatures())
	        {
	        	if ( sig.getOCSPCertificate() != null )
	        	{
		        	if (!sig.getOCSPCertificate().isValid())
		        	{
		        		korras=false;	        				
		        	}
	        	}
	        	Signatuur sigu = new Signatuur();
	        	sigu.setClaimedSigningTime(sig.getClaimedSigningTime());
	        	sigu.setIssuerName(sig.getSigningCertificate().issuerName());
	        	sigu.setSubjectName(sig.getSigningCertificate().getSubjectName());
	        	sigu.setErrors("");
	        	signatuurid.add(sigu);
		        log.info("Konteineri signatuur " + sig.getSigningCertificate().getSubjectName());  
		        log.info("Konteineri ClaimedSigningTime " + sig.getClaimedSigningTime());
		        log.info("Konteineri sertifikaadi issuer " + sig.getSigningCertificate().issuerName());
		        ValidationResult sres = sig.validateSignature();
		        log.info("Konteineri valideerimistulemuse vigasid " + sres.getErrors().size());
		        
		        if (sres.getErrors().size() > 0 )
		        {
		        	String vead = sres.getErrors().stream()
	    		        .map( n -> n.toString() )
	    		        .collect( Collectors.joining( ", " ) );
		        	sigu.setErrors(vead);
		        }

		        if (sres.getWarnings().size() > 0 )
		        {
		        	String vead = sres.getWarnings().stream()
	    		        .map( n -> n.toString() )
	    		        .collect( Collectors.joining( ", " ) );
		        	sigu.setErrors(sigu.getErrors()+" "+vead);
		        }		        
	        }
	        signad.setSignatuurid(signatuurid);
	        if (korras)
	        {
	        	signad.setResult(Digest.OK);
	        }
	        else
	        {
	        	signad.setResult(Digest.ERROR_INVALID_SIGNATURES);
	        }
            return signad;
        } catch (Exception e) {
            log.error("Error getContainerSignatures "+e.getMessage(), e);
        }
        return signad;
    }
    
    

    @RequestMapping(value="/getContainerToSign", method = RequestMethod.POST)
    public Digest getContainerToSign(@RequestParam String certInHex, @RequestParam MultipartFile file) { 
    	Digest digest = new Digest();
    	digest.setResult(Digest.ERROR_SIGNING);
        log.info("Olemasolevale konteinerile signatuur " + StringUtils.left(certInHex, 30) + "...");
        log.info("Konteiner " + file.getOriginalFilename());
        try
        {	            
	        byte[] fileBytes = file.getBytes();	
	        InputStream inputStream = new ByteArrayInputStream(fileBytes);
	        log.info("Konteineri loomine " + file.getOriginalFilename());  
	        Container container = BDocContainerBuilder.
	        	    aContainer(Container.DocumentType.ASICE).
	        	    fromStream(inputStream).	        	    
	        	    build();	        
	        
	        log.info("getContainerToSign Konteiner SignatureProfile " + container.getConfiguration().getSignatureProfile().toString());
	        log.info("getContainerToSign DataToSign "+StringUtils.left(certInHex, 30) + "...");  	        
	        DataToSign dataToSign = signer.getDataToSign(container, certInHex);		       
	        log.info("getContainerToSign DataToSign SignatureProfile " + dataToSign.getConfiguration().getSignatureProfile().name());

	        
	        log.info("DataToSign serialiseerimine");            
            byte[] data = SerializationUtils.serialize(dataToSign);            
            digest.setDataToSign(data);
            log.info("Genereerin konteineri räsi");
            String dataToSignInHex =
                    DatatypeConverter.printHexBinary(DSSUtils.digest(DigestAlgorithm.SHA256, dataToSign.getDataToSign()));
            digest.setHex(dataToSignInHex); 
            digest.setResult(Digest.OK);
            return digest;
        } catch (Exception e) {
            log.error("Error getContainerToSign "+e.getMessage(), e);
            digest.setResult("Error getContainerToSign "+e.getMessage());
        }
        return digest;
    }
    
    
    @RequestMapping(value="/addLTTMSignToContainer", method = RequestMethod.POST)
    public Digest addLTTMSignToContainer(@RequestParam String sertInHex,@RequestParam String signatureInHex
    		, @RequestParam MultipartFile file) {
    	Digest digest = new Digest();
    	Configuration configuration = Configuration.getInstance();
    	String ocspresponderstm = configuration.getAllowedOcspRespondersForTM().stream().collect(Collectors.joining(", "));
    	log.info("addLTTMSignToContainer Configuration AllowedOcspRespondersForTM "+ocspresponderstm);
    	log.info("addLTTMSignToContainer Configuration getOcspSource "+configuration.getOcspSource());
    	log.info("addLTTMSignToContainer Configuration getTspSource "+configuration.getTspSource());
    	log.info("addLTTMSignToContainer Configuration profile " + configuration.getSignatureProfile().name());
    	String profiil="";
    	configuration.setTrustedTerritories("EE");      	
    	digest.setResult(Digest.ERROR_SIGNING);
        log.info("Lisan olemasolevale konteinerile sertifikaati " + file.getOriginalFilename());
       
        try
        {	            
	        byte[] fileBytes = file.getBytes();	        
	        InputStream inputStream = new ByteArrayInputStream(fileBytes);
	        log.info("addLTTMSignToContainer Loome konteineri  " + file.getOriginalFilename());  
	        Container container = BDocContainerBuilder.
	        	    aContainer(Container.DocumentType.ASICE).  
	        	    withConfiguration(configuration).    	    
	        	    fromStream(inputStream).
	        	    build();        	        	        
	        
	        log.info("addLTTMSignToContainer Konteiner getCertificate"); 	        
	        X509Certificate signerCert = signer.getCertificate(sertInHex);	        
	        log.info("Certificate Name:"+signerCert.getSubjectDN().getName()); 	    
	        
	        log.info("addLTTMSignToContainer Konteiner SignatureBuilder");
	        org.digidoc4j.SignatureBuilder builder = org.digidoc4j.SignatureBuilder.
	        	    aSignature(container).
	        	    withSignatureDigestAlgorithm(org.digidoc4j.DigestAlgorithm.SHA256).
	        	    withSignatureProfile(Seadistus.getSignatureProfile()). 
	        	    withSigningCertificate(signerCert);
	        //Seadistus.getSignatureProfile()
	        log.info("addLTTMSignToContainer Konteiner DataToSign");
	        DataToSign dataToSign = builder.withSignatureProfile(Seadistus.getSignatureProfile()).buildDataToSign();	
	        profiil=dataToSign.getConfiguration().getSignatureProfile().name();
	        log.info("addLTTMSignToContainer DataToSign SignatureProfile: "+profiil);	        
	        log.info("addLTTMSignToContainer DataToSign TspSource: "+dataToSign.getConfiguration().getTspSource());	        
	        log.info("addLTTMSignToContainer DataToSign OcspSource: "+dataToSign.getConfiguration().getOcspSource());	 
	        log.info("addLTTMSignToContainer DataToSign AllowedOcspRespondersForTM: "+dataToSign.getConfiguration().getAllowedOcspRespondersForTM().stream().collect(Collectors.joining(", ")));
	        //dataToSign.getConfiguration().setTspSource("http://dd-at.ria.ee/tsa");	     
	        //log.info("DataToSign muudetud TspSource: "+dataToSign.getConfiguration().getTspSource());
	        	        
	        log.info("addLTTMSignToContainer DatatypeConverter.parseHexBinary "+signatureInHex);
	        byte[] serdibaidid = DatatypeConverter.parseHexBinary(signatureInHex);
	        
	        log.info("addLTTMSignToContainer DataToSign finalize "+serdibaidid.length); 
	        Signature signature = dataToSign.finalize(serdibaidid);
	        
	        //lisame konteinerile signatuuri
	        log.info("Konteiner addSignature, SubjectName: "+signature.getSigningCertificate().getSubjectName()); 
	        container.addSignature(signature);
	        
	        log.info("Konteiner container.saveAsStream"); 
            InputStream containerStream = container.saveAsStream();
            log.info("Konteiner IOUtils.toByteArray"); 
            byte[] containerdata = IOUtils.toByteArray(containerStream);
            
            log.info("Kontener digest.setContainer"); 
            digest.setContainer(containerdata);
            digest.setHex("application/vnd.etsi.asic-e+zip"); 
            digest.setResult(Digest.OK);
            return digest;
        } catch (Exception e) {
        	String cause="";
        	if (e.getCause() != null)
        	{
        		cause=e.getCause().getMessage();        		
        	}
            log.error("Error Viga konteinerile signatuuri lisamisel "+e.getMessage()+" "+cause+" Profiil:"+profiil, e);
            digest.setResult("Error Viga konteinerile signatuuri lisamisel "+e.getMessage()+" "+cause+" Profiil:"+profiil);
        }
        return digest;
    }    
    
    /*
    @RequestMapping(value="/addSignToContainer", method = RequestMethod.POST)
    public Digest addSignToContainer(@RequestParam String signatureInHex
    		, @RequestParam MultipartFile file, @RequestParam MultipartFile dfile) {
    	Digest digest = new Digest();
    	Configuration configuration = Configuration.getInstance();
    	
    	configuration.setTrustedTerritories("EE"); 
    	digest.setResult(Digest.ERROR_SIGNING);
        log.info("Lisan olemasolevale konteinerile signatuuri " + StringUtils.left(signatureInHex, 30) + "...");
        log.info("Konteiner " + file.getOriginalFilename());
        log.info("DataToSign " + dfile.getOriginalFilename());
        log.info("Configuration profile " + configuration.getSignatureProfile().toString());
        try
        {	            
	        byte[] fileBytes = file.getBytes();	        
	        InputStream inputStream = new ByteArrayInputStream(fileBytes);
	        log.info("Loome konteineri  " + file.getOriginalFilename());  
	        Container container = BDocContainerBuilder.
	        	    aContainer(Container.DocumentType.BDOC).  // Container type is BDoc
	        	    withConfiguration(configuration).	        	    
	        	    fromStream(inputStream).
	        	    build();
	        
	        log.info("Olemasoleva konteineri signatuurid " + file.getOriginalFilename()); 
	        for (Signature sig : container.getSignatures())
	        {
		        log.info("Signatuur " + sig.getSigningCertificate().getSubjectName());  
		        log.info("Signatuuri ClaimedSigningTime " + sig.getClaimedSigningTime());
		        log.info("Signatuuri sertifikaadi issuer " + sig.getSigningCertificate().issuerName());
		        if ( sig.getOCSPCertificate() != null )
	        	{
		        	if (sig.getOCSPCertificate().isValid())
		        	{
		        		log.info("Signatuuri OSCP isvalid " + sig.getOCSPCertificate().isValid());         				
		        	}
	        	}
	        }	        	        
	        
	        log.info("Konteiner SignatureProfile " + container.getConfiguration().getSignatureProfile().toString());
	        
	        //deserialiseerime datatosign 	        
	        fileBytes = dfile.getBytes();	        
	        log.info("Konteiner DataToSign SerializationUtils.deserialize, fileBytes Pikkus: "+fileBytes.length); 
	        DataToSign dataToSign = (DataToSign) SerializationUtils.deserialize(fileBytes);
	        
	        log.info("Konteiner DataToSign TspSource: "+dataToSign.getConfiguration().getTspSource());
	        	        
	        dataToSign.getConfiguration().setTspSource("http://dd-at.ria.ee/tsa");	        
	        	        	       
	        log.info("Konteiner DataToSign getIssuerDN"); 
	        String issn=dataToSign.getSignatureParameters().getSigningCertificate().getIssuerDN().getName();
	        if (issn != null)
	        {
	        	log.info("Konteiner DataToSign IssuerDN "+issn);
	        }
	        	
	        log.info("Konteiner DataToSign SignatureProfile "+dataToSign.getConfiguration().getSignatureProfile().toString());

	        log.info("DatatypeConverter.parseHexBinary "+signatureInHex);
	        byte[] serdibaidid = DatatypeConverter.parseHexBinary(signatureInHex);
	        	        
	        log.info("Konteiner DataToSign finalize "+serdibaidid.length); 
	        Signature signature = dataToSign.finalize(serdibaidid);
	        
	        //lisame konteinerile signatuuri
	        log.info("Konteiner addSignature subject: "+signature.getSigningCertificate().getSubjectName()); 
	        container.addSignature(signature);
	        
	        log.info("Konteiner container.saveAsStream"); 
            InputStream containerStream = container.saveAsStream();
            log.info("Konteiner IOUtils.toByteArray"); 
            byte[] containerdata = IOUtils.toByteArray(containerStream);
            
            //byte[] containerdata = SerializationUtils.serialize(container);
            log.info("Kontener digest.setContainer"); 
            digest.setContainer(containerdata);
            digest.setHex("application/vnd.etsi.asic-e+zip"); //BDOC
            digest.setResult(Digest.OK);
            return digest;
        } catch (Exception e) {
        	String cause="";
        	if (e.getCause() != null)
        	{
        		cause=e.getCause().getMessage();        		
        	}
            log.error("Error Viga konteinerile signatuuri lisamisel "+e.getMessage()+" "+cause, e);
            digest.setResult("Error Viga konteinerile signatuuri lisamisel "+e.getMessage()+" "+cause);
        }
        return digest;
    }    
    */
    
    @RequestMapping(value="/validateContainer", method = RequestMethod.POST)
    public Valideerimine validateContainer(@RequestParam MultipartFile file) {
    	Valideerimine valideerimine = new Valideerimine(Valideerimine.VALIDATION_ERRORS);
        log.info("valideerin konteinerit " + file.getOriginalFilename());    
        try
        {	            
	        byte[] fileBytes = file.getBytes();	        
	        InputStream inputStream = new ByteArrayInputStream(fileBytes);
	        log.info("Konteineri signatuurid " + file.getOriginalFilename());  
	        Container container = BDocContainerBuilder.
	        	    aContainer(Container.DocumentType.ASICE).  
	        	    fromStream(inputStream).
	        	    build();
	        ContainerValidationResult cvr = container.validate();
	        if (cvr.isValid())
	        {
	        	valideerimine.setResult(Digest.OK);
	        }
	        else
	        {	        	
	        	List<DigiDoc4JException> dde = cvr.getErrors();
	        	String errors = dde.stream()
	        			.map(error -> error.getMessage())
	        			.collect(Collectors.joining(", ", "[", "]"));	        	
	        	valideerimine.setErrors(errors);
	        	if (cvr.hasWarnings())
	        	{
		        	dde = cvr.getWarnings();
		        	errors = dde.stream()
		        			.map(error -> error.getMessage())
		        			.collect(Collectors.joining(", ", "[", "]"));	        	
		        	valideerimine.setWarnings(errors);
	        	}
	        	List<SignatureValidationReport> rep = cvr.getReports();
	        	if (rep.size() > 0)
	        	{
		        	StringBuilder sb = new StringBuilder();
		        	for (SignatureValidationReport repo : rep)
		        	{
		        		
		        		errors = repo.getErrors().stream()
		        			.map(error -> error)
		        			.collect(Collectors.joining(", ", "[", "]"));
		        		sb.append(errors);
		        	}
		        	valideerimine.setReports(sb.toString());
	        	}

	        }
            return valideerimine;
        } catch (Exception e) {
            log.error("Error validateContainer "+e.getMessage(), e);
        }
        return valideerimine;
    }

    @RequestMapping(value="/getContainerFiles", method = RequestMethod.POST)
    public Failid getContainerFiles(@RequestParam MultipartFile file) {
    	Failid signad = new Failid();
    	signad.setResult(Digest.ERROR_GETTING_FILES);
        log.info("Konteineri failid " + StringUtils.left(file.toString(), 20) + "...");    
        try
        {
	        //loome konteineri	        
	        byte[] fileBytes = file.getBytes();	        
	        InputStream inputStream = new ByteArrayInputStream(fileBytes);
	        log.info("Konteineri failid " + StringUtils.left(file.toString(), 20) + "...");  
	        Container container = BDocContainerBuilder.
	        	    aContainer(Container.DocumentType.ASICE).  
	        	    fromStream(inputStream).
	        	    build();
	        log.info("Konteineri faile kokku " + container.getDataFiles().size());  
	        ArrayList<String> sid = new ArrayList<String>();
	        for (DataFile sig : container.getDataFiles())
	        {
	        	sid.add(sig.getName());
		        log.debug("Konteineri fail " + sig.getName());		               
	        }
	        signad.setFailid(sid);
	        signad.setResult(Digest.OK);
            return signad;
        } catch (Exception e) {
            log.error("Error Viga getContainerFiles "+e.getMessage(), e);
        }
        return signad;
    }
    
    /*
    public byte[] decodeHexString(String hexString) {
        if (hexString.length() % 2 == 1) {
            throw new IllegalArgumentException(
              "Invalid hexadecimal String supplied.");
        }
         
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < hexString.length(); i += 2) {
            bytes[i / 2] = hexToByte(hexString.substring(i, i + 2));
        }
        return bytes;
    }
    
    public byte hexToByte(String hexString) {
        int firstDigit = toDigit(hexString.charAt(0));
        int secondDigit = toDigit(hexString.charAt(1));
        return (byte) ((firstDigit << 4) + secondDigit);
    }
    
    private int toDigit(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if(digit == -1) {
            throw new IllegalArgumentException(
              "Invalid Hexadecimal Character: "+ hexChar);
        }
        return digit;
    }
    */
}