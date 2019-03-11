package web.bdoc.controllers;
//koopia DigiDoc4j Hwcrypto Demo
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import web.bdoc.model.Digest;
import web.bdoc.model.Failid;
import web.bdoc.model.Signatuur;
import web.bdoc.model.Signatuurid;
import web.bdoc.model.Valideerimine;
import web.bdoc.signature.FileSigner;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.SerializationUtils;
import org.apache.commons.lang3.StringUtils;
import org.digidoc4j.Container;
import org.digidoc4j.ContainerBuilder;
import org.digidoc4j.ContainerValidationResult;
import org.digidoc4j.DataFile;
import org.digidoc4j.DataToSign;
import org.digidoc4j.Signature;
import org.digidoc4j.SignatureBuilder;
import org.digidoc4j.ValidationResult;
import org.digidoc4j.exceptions.DigiDoc4JException;
import org.digidoc4j.impl.asic.asice.bdoc.BDocSignature;
import org.digidoc4j.impl.asic.report.SignatureValidationReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
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
    	
        log.debug("Töötlen ülesse laetud faile räsi jaoks"+ff);
        try {
            byte[] fileBytes = failid[0].getBytes();
            String fileName = failid[0].getOriginalFilename();
            String mimeType = failid[0].getContentType();
            DataFile dataFile = new DataFile(fileBytes, fileName, mimeType);
            log.debug("Loon ülesse laetud failide jaoks konteineri");
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
            //serialiseerime            
            byte[] data = SerializationUtils.serialize(dataToSign);            
            digest.setDataToSign(data);
            log.debug("Genereerin konteineri räsi");
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
        log.debug("Töötlen ülesse laetud faili räsi jaoks"+file.getOriginalFilename());
        try {
            byte[] fileBytes = file.getBytes();
            String fileName = file.getOriginalFilename();
            String mimeType = file.getContentType();
            DataFile dataFile = new DataFile(fileBytes, fileName, mimeType);
            log.debug("Loon ülesse laetud faili jaoks konteineri");
            Container container = signer.createContainer(dataFile);            
                        
            //serialiseerime konteineri
            byte[] containerdata = SerializationUtils.serialize(container);
            digest.setContainer(containerdata);
            
            DataToSign dataToSign = signer.getDataToSign(container, certInHex);
            //serialiseerime            
            byte[] data = SerializationUtils.serialize(dataToSign);            
            digest.setDataToSign(data);
            log.debug("Genereerin konteineri räsi");
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
        log.debug("Loon konteinerit signatuuri jaoks " + StringUtils.left(signatureInHex, 20) + "...");
        log.debug("DataToSign " + StringUtils.left(dfile.toString(), 20) + "...");
        log.debug("Konteiner " + StringUtils.left(file.toString(), 20) + "...");    
        try
        {
	        //deserialiseerime konteineri	        
	        byte[] fileBytes = file.getBytes();	        
	        Container container = (Container) SerializationUtils.deserialize(fileBytes);
	        
	        //deserialiseerime datatosign 	        
	        fileBytes = dfile.getBytes();	        
	        DataToSign dataToSign = (DataToSign) SerializationUtils.deserialize(fileBytes);
                           
	        //lisame konteinerile signatuuri
            signer.signContainer(container, dataToSign, signatureInHex);
            InputStream containerStream = container.saveAsStream();
            byte[] containerdata = IOUtils.toByteArray(containerStream);
            
            //byte[] containerdata = SerializationUtils.serialize(container);
            digest.setContainer(containerdata);
            //digest.setDataToSign(SerializationUtils.serialize(container));
            digest.setResult(Digest.OK);
            digest.setHex("application/vnd.etsi.asic-e+zip"); //BDOC
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
        log.debug("Konteineri signatuurid " + StringUtils.left(file.toString(), 20) + "...");    
        try
        {
	        //loome konteineri	        
	        byte[] fileBytes = file.getBytes();	        
	        InputStream inputStream = new ByteArrayInputStream(fileBytes);
	        log.debug("Konteineri signatuurid " + StringUtils.left(file.toString(), 20) + "...");  
	        Container container = ContainerBuilder.
	        	    aContainer(Container.DocumentType.BDOC).  // Container type is BDoc
	        	    fromStream(inputStream).
	        	    build();
	        log.debug("Konteineri signatuure kokku " + container.getSignatures().size());  
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
		        log.debug("Konteineri signatuur " + sig.getSigningCertificate().getSubjectName());  
		        log.debug("Konteineri ClaimedSigningTime " + sig.getClaimedSigningTime());
		        log.debug("Konteineri ClaimedSigningTime " + sig.getSigningCertificate().issuerName());
		        ValidationResult sres = sig.validateSignature();
		        log.debug("Konteineri valideerimistulemuse vigasid " + sres.getErrors().size());
		        
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
            log.error("Error Viga signatuuride küsimisel "+e.getMessage(), e);
        }
        return signad;
    }
    
    

    @RequestMapping(value="/getContainerToSign", method = RequestMethod.POST)
    public Digest getContainerToSign(@RequestParam String certInHex, @RequestParam MultipartFile file) {
    	Digest digest = new Digest();
    	digest.setResult(Digest.ERROR_SIGNING);
        log.debug("Küsin olemasolevale konteinerile signatuuri " + StringUtils.left(certInHex, 20) + "...");
        log.debug("Konteiner " + StringUtils.left(file.toString(), 20) + "...");    
        try
        {	            
	        byte[] fileBytes = file.getBytes();	        
	        InputStream inputStream = new ByteArrayInputStream(fileBytes);
	        log.debug("Konteineri signatuurid " + StringUtils.left(file.toString(), 20) + "...");  
	        Container container = ContainerBuilder.
	        	    aContainer(Container.DocumentType.BDOC).  
	        	    fromStream(inputStream).
	        	    build();
	        
	        DataToSign dataToSign = signer.getDataToSign(container, certInHex);
	        //serialiseerime            
            byte[] data = SerializationUtils.serialize(dataToSign);            
            digest.setDataToSign(data);
            log.debug("Genereerin konteineri räsi");
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
    
    
    @RequestMapping(value="/addSignToContainer", method = RequestMethod.POST)
    public Digest addSignToContainer(@RequestParam String signatureInHex
    		, @RequestParam MultipartFile file, @RequestParam MultipartFile dfile) {
    	Digest digest = new Digest();
    	digest.setResult(Digest.ERROR_SIGNING);
        log.debug("Lisan olemasolevale konteinerile signatuuri " + StringUtils.left(signatureInHex, 20) + "...");
        log.debug("Konteiner " + StringUtils.left(file.toString(), 20) + "...");    
        try
        {	            
	        byte[] fileBytes = file.getBytes();	        
	        InputStream inputStream = new ByteArrayInputStream(fileBytes);
	        log.debug("Konteineri signatuurid " + StringUtils.left(file.toString(), 20) + "...");  
	        Container container = ContainerBuilder.
	        	    aContainer(Container.DocumentType.BDOC).  // Container type is BDoc
	        	    fromStream(inputStream).
	        	    build();
	        
	        //deserialiseerime datatosign 	        
	        fileBytes = dfile.getBytes();	        
	        DataToSign dataToSign = (DataToSign) SerializationUtils.deserialize(fileBytes);

		    //Finalize the signature with OCSP response and timestamp (or timemark)
	        Signature signature = dataToSign.finalize(signatureInHex.getBytes());

	        //lisame konteinerile signatuuri
	        container.addSignature(signature);
	        
	        //lisame konteinerile signatuuri
            //signer.signContainer(container, dataToSign, signatureInHex);
            
            
            InputStream containerStream = container.saveAsStream();
            byte[] containerdata = IOUtils.toByteArray(containerStream);
            
            //byte[] containerdata = SerializationUtils.serialize(container);
            digest.setContainer(containerdata);
            digest.setHex("application/vnd.etsi.asic-e+zip"); //BDOC
            digest.setResult(Digest.OK);
            return digest;
        } catch (Exception e) {
            log.error("Error Viga konteinerile signatuuri lisamisel "+e.getMessage(), e);
            digest.setResult("Error Viga konteinerile signatuuri lisamisel "+e.getMessage());
        }
        return digest;
    }    
    
 // Signer's certificate information: ID Code, first name, last name, country code etc.
//    X509Cert certificate = signature.getSigningCertificate();
//    String signerIdCode = certificate.getSubjectName(SERIALNUMBER);
//    String signerFirstName = certificate.getSubjectName(GIVENNAME);
//    String signerLastName = certificate.getSubjectName(SURNAME);
//    String signerCountryCode = certificate.getSubjectName(C);    
    
    
    @RequestMapping(value="/validateContainer", method = RequestMethod.POST)
    public Valideerimine validateContainer(@RequestParam MultipartFile file) {
    	Valideerimine valideerimine = new Valideerimine(Valideerimine.VALIDATION_ERRORS);
        log.debug("valideerin konteinerit " + StringUtils.left(file.toString(), 20) + "...");    
        try
        {	            
	        byte[] fileBytes = file.getBytes();	        
	        InputStream inputStream = new ByteArrayInputStream(fileBytes);
	        log.debug("Konteineri signatuurid " + StringUtils.left(file.toString(), 20) + "...");  
	        Container container = ContainerBuilder.
	        	    aContainer(Container.DocumentType.BDOC).  
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
        log.debug("Konteineri failid " + StringUtils.left(file.toString(), 20) + "...");    
        try
        {
	        //loome konteineri	        
	        byte[] fileBytes = file.getBytes();	        
	        InputStream inputStream = new ByteArrayInputStream(fileBytes);
	        log.debug("Konteineri failid " + StringUtils.left(file.toString(), 20) + "...");  
	        Container container = ContainerBuilder.
	        	    aContainer(Container.DocumentType.BDOC).  // Container type is BDoc
	        	    fromStream(inputStream).
	        	    build();
	        log.debug("Konteineri faile kokku " + container.getDataFiles().size());  
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
            log.error("Viga failide küsimisel "+e.getMessage(), e);
        }
        return signad;
    }
    
}