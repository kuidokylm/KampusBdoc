package web.bdoc.model;

import java.util.ArrayList;

public class Failid {


	private ArrayList<String> failid;
	private String result;

	public ArrayList<String> getFailid() {
		return this.failid;
	}

	public void setFailid(ArrayList<String> values) {
		this.failid = new ArrayList<String>();
		this.failid.addAll(values);
	}

	public String getResult() {
		return this.result;
	}

	public void setResult(String result) {
		this.result = result;
	}
}
