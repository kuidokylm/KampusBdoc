package web.bdoc.model;

import java.util.ArrayList;

public class Signatuurid {
	
	private ArrayList<Signatuur> signatuurid;
	private String result;

	public ArrayList<Signatuur> getSignatuurid() {
		return this.signatuurid;
	}

	public void setSignatuurid(ArrayList<Signatuur> values) {
		this.signatuurid = new ArrayList<Signatuur>();
		this.signatuurid.addAll(values);
	}

	public String getResult() {
		return this.result;
	}

	public void setResult(String result) {
		this.result = result;
	}
	

}
