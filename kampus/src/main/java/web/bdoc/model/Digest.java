package web.bdoc.model;

import org.digidoc4j.DataToSign;

//koopia DigiDoc4j Hwcrypto Demo

public class Digest{


    public static final String OK = "ok";
    public static final String ERROR_GENERATING_HASH = "error_generating_hash";
    public static final String ERROR_INVALID_SIGNATURES = "error_invalid_signature";
    public static final String ERROR_SIGNING = "error_signing_file";
    public static final String ERROR_GETTING_SIGNATURES = "error_getting_signatures";

    private String result;
	private byte[] container;
	private byte[] dataToSign;	
    private String hex;

    public Digest() {
    }

    public Digest(String result) {
        this.result = result;
    }

    public static Digest resultOk() {
        return new Digest(OK);
    }

    public static Digest resultSigningError() {
        return new Digest(ERROR_SIGNING);
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }
	

    public String getHex() {
        return this.hex;
    }

    public void setHex(String hex) {
        this.hex = hex;
    }

	public byte[] getDataToSign() {
		return dataToSign;
	}

	public void setDataToSign(byte[] dataToSign) {
		this.dataToSign = dataToSign;
	}

	public byte[] getContainer() {
		return container;
	}

	public void setContainer(byte[] container) {
		this.container = container;
	}

}
