package com.daon.idxAuthRequestNode;

public class ProcessTokenRequest 
{
	private String name;
	private String processDefnName;
	private String processDefnVersion;
	private String status;
	private String type;
	private String uiUrl;
	private ProcessTokenParameters parameters;
	
	public String getName() 
	{
		return name;
	}

	public void setName(String name) 
	{
		this.name = name;
	}

	public String getProcessDefnName() 
	{
		return processDefnName;
	}

	public void setProcessDefnName(String processDefnName) 
	{
		this.processDefnName = processDefnName;
	}

	public String getProcessDefnVersion() 
	{
		return processDefnVersion;
	}

	public void setProcessDefnVersion(String processDefnVersion) 
	{
		this.processDefnVersion = processDefnVersion;
	}

	public String getStatus() 
	{
		return status;
	}

	public void setStatus(String status) 
	{
		this.status = status;
	}

	public String getType() 
	{
		return type;
	}

	public void setType(String type) 
	{
		this.type = type;
	}

	public String getUiUrl() 
	{
		return uiUrl;
	}

	public void setUiUrl(String uiUrl) 
	{
		this.uiUrl = uiUrl;
	}

	public ProcessTokenParameters getParameters() 
	{
		return parameters;
	}

	public void setParameters(ProcessTokenParameters parameters) 
	{
		this.parameters = parameters;
	}
}
