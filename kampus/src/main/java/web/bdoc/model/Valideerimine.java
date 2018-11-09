package web.bdoc.model;

public class Valideerimine {
	
	public static final String OK = "ok";
    public static final String VALIDATION_ERRORS = "validation errors";
    
	private String result;
	private String errors;
	private String warnings;
	private String reports;
	

	public Valideerimine() {
	    }

    public Valideerimine(String result) {
        this.result = result;
    }
	    
	public String getResult() {
		return result;
	}

	public void setResult(String result) {
		this.result = result;
	}

	public String getErrors() {
		return errors;
	}

	public void setErrors(String errors) {
		this.errors = errors;
	}

	public String getWarnings() {
		return warnings;
	}

	public void setWarnings(String warnings) {
		this.warnings = warnings;
	}

	public String getReports() {
		return reports;
	}

	public void setReports(String reports) {
		this.reports = reports;
	}

}
