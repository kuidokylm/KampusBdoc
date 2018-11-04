package web.bdoc.model;

import java.util.Date;

public class Signatuur {
	
	private String SubjectName;
	private Date ClaimedSigningTime;
	private String issuerName;
	
	public String getSubjectName()
	{
		return this.SubjectName;
	}
	
	public void setSubjectName(String value)
	{
		this.SubjectName=value;
	}

	public Date getClaimedSigningTime() {
		return this.ClaimedSigningTime;
	}

	public void setClaimedSigningTime(Date claimedSigningTime) {
		this.ClaimedSigningTime = claimedSigningTime;
	}

	public String getIssuerName() {
		return this.issuerName;
	}

	public void setIssuerName(String issuerName) {
		this.issuerName = issuerName;
	}
	

}
