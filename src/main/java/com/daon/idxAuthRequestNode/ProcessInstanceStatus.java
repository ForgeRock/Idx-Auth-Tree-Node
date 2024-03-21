package com.daon.idxAuthRequestNode;

public class ProcessInstanceStatus 
{
	private String id;
	private String tenantId;
	private String processDefnId;
	private String processDefnName;
	private String processDefnVersion;
	private String lastName;
	private String firstName;
	private String createdAt;
	private String elapsedMilliseconds;
	private String status;
	private String statusMapped;
	
	public String getId() 
	{
		return id;
	}
	
	public void setId(String id) 
	{
		this.id = id;
	}
	
	public String getTenantId() 
	{
		return tenantId;
	}
	
	public void setTenantId(String tenantId) 
	{
		this.tenantId = tenantId;
	}
	
	public String getProcessDefnId() 
	{
		return processDefnId;
	}
	
	public void setProcessDefnId(String processDefnId) 
	{
		this.processDefnId = processDefnId;
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
	
	public String getLastName() 
	{
		return lastName;
	}
	
	public void setLastName(String lastName) 
	{
		this.lastName = lastName;
	}
	
	public String getFirstName() 
	{
		return firstName;
	}
	
	public void setFirstName(String firstName) 
	{
		this.firstName = firstName;
	}
	
	public String getCreatedAt() 
	{
		return createdAt;
	}
	
	public void setCreatedAt(String createdAt) 
	{
		this.createdAt = createdAt;
	}
	
	public String getElapsedMilliseconds() 
	{
		return elapsedMilliseconds;
	}
	
	public void setElapsedMilliseconds(String elapsedMilliseconds) 
	{
		this.elapsedMilliseconds = elapsedMilliseconds;
	}
	
	public String getStatus() 
	{
		return status;
	}
	
	public void setStatus(String status) 
	{
		this.status = status;
	}
	
	public String getStatusMapped() 
	{
		return statusMapped;
	}
	
	public void setStatusMapped(String statusMapped) 
	{
		this.statusMapped = statusMapped;
	}
}
