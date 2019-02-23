package web.bdoc.configuration;

import org.digidoc4j.SignatureProfile;

public final class Seadistus {
	
	public static SignatureProfile getSignatureProfile()
	{
		return SignatureProfile.B_BES;  //PROD reshiimis ei tee OSCP päringut //kasuta arenduses
		//return SignatureProfile.LT_TM; ///BDOC Time-mark, similar to LT (BDoc 2.1 format).  //kasuta seda produktsioonis    
		//Note that BES signatures are missing OCSP (and Timestamp) and therefore are not valid as digital signatures by the law
	}
	
	public static String getSignatureProfileName()
	{
		return getSignatureProfile().name();
	}
}
