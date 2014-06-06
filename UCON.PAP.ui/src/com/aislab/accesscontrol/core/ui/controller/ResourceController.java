/******************************************************************************
 * Project:    Extensible Access Control Framework for Cloud based Applications.
 *                     http://ais.seecs.nust.edu.pk/project/ 
 * Developed by: KTH- Applied Information Security Lab (AIS), 
 *                       NUST-SEECS, H-12 Campus, 
 *                       Islamabad, Pakistan. 
 *                       www.ais.seecs.nust.edu.pk
 * Funded by: National ICT R&D Fund, Ministry of Information Technology & Telecom,
 *                  http://www.ictrdf.org.pk/
 * Copyright (c) 2013-2015 All Rights Reserved, AIS-SEECS NUST & National ICT R&D Fund

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy and/or modify the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software. 

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *****************************************************************************/
package com.aislab.accesscontrol.core.ui.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;

import com.aislab.accesscontrol.core.entities.ResAttrValues;
import com.aislab.accesscontrol.core.entities.Resource;
import com.aislab.accesscontrol.core.entities.ResourceAttribute;
import com.aislab.accesscontrol.core.ui.dao.ResAttrValuesDAO;
import com.aislab.accesscontrol.core.ui.dao.ResourceAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.ResourceDAO;

/**
 * A session scoped, managed bean for user interfaces related to
 * {@code Resource}
 * 
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 * 
 * 
 * 
 */
@ManagedBean
@SessionScoped
public class ResourceController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(ResourceController.class.getName());

	/**
	 * A String variable to store the value of {@code resAttrId} attribute of
	 * {@code ResourceAttribute} while adding a new {@code ResourceAttribute}
	 * corresponding to an existing {@code Resource} instance.
	 */
	String newAttributeName = null;
	/**
	 * A String variable to store the value of {@code resAttrValue} attribute of
	 * {@code ResAttrValues} while adding a new {@code ResourceAttribute}
	 * corresponding to an existing {@code Resource} instance.
	 */
	String newAttributeValue = null;

	/**
	 * A {@code List} of {@code String} representing the available data types
	 * for adding a new {@code ResourceAttribute} corresponding to an exiting
	 * {@code Resource} instance.
	 */
	boolean attrbtn = true;
	/**
	 * A boolean variable to check whether any {@code ResourceAttribute}
	 * instance is selected by the user so that the corresponding
	 * {@code ResAttrValue} instance can be added. By default it is set to
	 * {@code TRUE} so that the corresponding add button is disabled while it is
	 * becomes {@code FALSE} if any {@code ResourceAttribute} instance is
	 * selected in the user interface.
	 */
	boolean attrValuebtn = true;
	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed in a modification operation. By default it is set to
	 * {@code TRUE} while it is becomes {@code FALSE} if {@code Save} is
	 * pressed.
	 * 
	 */
	boolean operationFail = true;
	/**
	 * An instance of {@code ResourceDAO} for using methods to access data
	 * related to {@code Resource}
	 */
	ResourceDAO daoResource = new ResourceDAO();
	/**
	 * An instance of {@code ResourceAttributeDAO} for using methods to access
	 * data related to {@code ResourceAttribute}
	 */
	ResourceAttributeDAO daoResourceAttribute = new ResourceAttributeDAO();
	/**
	 * An instance of {@code ResAttrValuesDAO} for using methods to access data
	 * related to {@code ResAttrValues}
	 */

	ResAttrValuesDAO daoResourceAttributeValue = new ResAttrValuesDAO();
	/**
	 * An instance of {@code Resource} used to store the {@code Resource}
	 * selected by the user from the user interface.
	 */
	public Resource selectedResource;;
	/**
	 * An ArrayList of {@code Resource} used to display all the existing
	 * {@code Resource}s stored in the database.
	 */
	public ArrayList<Resource> resourceList = new ArrayList<Resource>();
	/**
	 * A String variable to store the value of {@code dataType} attribute of
	 * {@code ResourceAttribute} while adding a new {@code ResourceAttribute}
	 * corresponding to an exiting {@code Resource} instance.
	 */
	String selectedDataType = null;
	/**
	 * A {@code List} of {@code String} representing the available data types
	 * for adding a new {@code ResourceAttribute} corresponding to an exiting
	 * {@code Resource} instance.
	 */
	List<String> dataTypeList = Arrays.asList("String", "Integer", "Boolean",
			"anyURI");

	/**
	 * An ArrayList of {@code ResourceAttribute} used to display all the
	 * existing {@code ResourceAttribute}(s) stored in the database. These
	 * {@code ResourceAttribute}(s) are related to a particular {@code Resource}
	 * instance stored in {@code selectedResource}.
	 */
	public ArrayList<ResourceAttribute> resourceAttributeList = new ArrayList<ResourceAttribute>();
	/**
	 * An instance of {@code ResourceAttribute} used to store the
	 * {@code ResourceAttribute} selected by the user from the user interface.
	 */
	public ResourceAttribute selectedResourceAttributes;
	/**
	 * An ArrayList of {@code ResAttrValues} used to display all the existing
	 * {@code ResAttrValues}(s) stored in the database. These
	 * {@code ResAttrValues}(s) are related to a particular
	 * {@code ResourceAttribute} instance stored in
	 * {@code selectedResourceAttributes}.
	 */

	public ArrayList<ResAttrValues> resourceAttributeValueList;
	/**
	 * An instance of {@code ResAttrValues} used to store the
	 * {@code ResAttrValues} selected by the user from the user interface.
	 */
	public ResAttrValues selectedResourceAttributeValue;

	/*-------------------------------------------------------------------------*/
	/*-------------------------------------------------------------------------*/
	/**
	 * Sets the {@code selectedDataType} property to {@code String} argument
	 * 
	 * @param selectedDataType
	 */

	public void setSelectedDataType(String selectedDataType) {
		this.selectedDataType = selectedDataType;
		log.debug("Set  selectedDataType: " + selectedDataType);
	}

	/**
	 * Sets the {@code ResourceAttributeValueList} property to
	 * {@code ResAttrValues} argument.
	 * 
	 * @param ResourceAttributeValueList
	 */
	public void setResourceAttributeValueList(
			ArrayList<ResAttrValues> resourceAttributeValueList) {
		this.resourceAttributeValueList = resourceAttributeValueList;
		log.debug("Set  resourceAttributeValueList: "
				+ resourceAttributeValueList);
	}

	/**
	 * Sets the {@code operationFail} property to {@code boolean} argument.
	 * 
	 * @param operationFail
	 */
	public void setOperationFail(boolean operationFail) {
		this.operationFail = operationFail;
		log.debug("Set  operationFail: " + operationFail);
	}

	/**
	 * Sets the {@code newAttributeName} property to {@code String} argument.
	 * 
	 * @param newAttributeName
	 */
	public void setNewAttributeName(String newAttributeName) {
		this.newAttributeName = newAttributeName;
		log.debug("Set  newAttributeName: " + newAttributeName);
	}

	/**
	 * Sets the {@code selectedResourceAttributeValue} property to
	 * {@code ResAttrValues} argument.
	 * 
	 * @param selectedResourceAttributeValue
	 */
	public void setSelectedResourceAttributeValue(
			ResAttrValues selectedResourceAttributeValue) {
		this.selectedResourceAttributeValue = selectedResourceAttributeValue;
		log.debug("Set  selectedResourceAttributeValue: "
				+ selectedResourceAttributeValue);
	}

	/**
	 * Sets the {@code daoResource} property to {@code ResourceDAO} argument.
	 * 
	 * @param daoResource
	 */
	public void setDaoResource(ResourceDAO daoResource) {
		this.daoResource = daoResource;
		log.debug("Set  daoResource: " + daoResource);
	}

	/**
	 * Sets the {@code daoResourceAttribute} property to
	 * {@code ResourceAttributeDAO} argument.
	 * 
	 * @param daoResourceAttribute
	 */
	public void setDaoResourceAttribute(
			ResourceAttributeDAO daoResourceAttribute) {
		this.daoResourceAttribute = daoResourceAttribute;
		log.debug("Set  daoResourceAttribute: " + daoResourceAttribute);
	}

	/**
	 * Sets the {@code daoResourceAttributeValue} property to
	 * {@code ResAttrValuesDAO} argument.
	 * 
	 * @param daoResourceAttributeValue
	 */

	public void setDaoResourceAttributeValue(
			ResAttrValuesDAO daoResourceAttributeValue) {
		this.daoResourceAttributeValue = daoResourceAttributeValue;
		log.debug("Set  daoResourceAttributeValue: "
				+ daoResourceAttributeValue);
	}

	/**
	 * Sets the {@code selectedResource} property to {@code Resource} argument.
	 * 
	 * @param selectedResource
	 */
	public void setSelectedResource(Resource selectedResource) {

		this.setAttrbtn(false);
		this.resourceAttributeValueList = new ArrayList<ResAttrValues>();
		this.selectedResourceAttributes = null;
		this.selectedResource = selectedResource;

		log.debug("Set  selectedResource: " + selectedResource);
	}

	/**
	 * Sets the {@code selectedResourceAttributes} property to
	 * {@code ResourceAttribute} argument.
	 * 
	 * @param selectedResourceAttributes
	 */
	public void setSelectedResourceAttributes(
			ResourceAttribute selectedResourceAttributes) {
		this.setAttrValuebtn(false);
		this.selectedResourceAttributes = selectedResourceAttributes;
		log.debug("Set  selectedResourceAttributes: "
				+ selectedResourceAttributes);
	}

	/**
	 * Sets the {@code ResourceAttributeList} property to
	 * {@code ResourceAttribute} argument.
	 * 
	 * @param ResourceAttributeList
	 */
	public void setResourceAttributeList(
			ArrayList<ResourceAttribute> resourceAttributeList) {
		this.resourceAttributeList = resourceAttributeList;
		log.debug("Set  resourceAttributeList: " + resourceAttributeList);
	}

	/**
	 * Sets the {@code ResourceList} property to {@code Resource} argument.
	 * 
	 * @param ResourceList
	 */
	public void setResourceList(ArrayList<Resource> resourceList) {
		this.resourceList = resourceList;
		log.debug("Set  resourceList: " + resourceList);
	}

	/**
	 * Sets the {@code newAttributeValue} property to {@code String} argument.
	 * 
	 * @param newAttributeValue
	 */
	public void setNewAttributeValue(String newAttributeValue) {
		this.newAttributeValue = newAttributeValue;
		log.debug("Set  newAttributeValue: " + newAttributeValue);
	}

	/**
	 * Sets the {@code dataTypeList} property to {@code List} argument
	 * 
	 * @param dataTypeList
	 */
	public void setDataTypeList(List<String> dataTypeList) {
		this.dataTypeList = dataTypeList;
		log.debug("Set  dataTypeList: " + dataTypeList);
	}

	/**
	 * Sets the {@code attrValuebtn} property to {@code boolean} argument.
	 * 
	 * @param attrValuebtn
	 */
	public void setAttrValuebtn(boolean attrvaluebtn) {
		this.attrValuebtn = attrvaluebtn;
		log.debug("Set  attrValuebtn: " + attrValuebtn);
	}

	/**
	 * Sets the {@code attrbtn} property to {@code boolean} argument.
	 * 
	 * @param attrbtn
	 */
	public void setAttrbtn(boolean attrbtn) {
		this.attrbtn = attrbtn;
		log.debug("Set  attrbtn: " + attrbtn);
	}

	/*-------------------------------------------------------------------------*/
	/*-------------------------------------------------------------------------*/
	/**
	 * Returns the value of {@code selectedDataType} property
	 * 
	 * @return selectedDataType
	 */
	public String getSelectedDataType() {
		log.debug("Get  selectedDataType: " + selectedDataType);

		return selectedDataType;
	}

	/**
	 * Returns the value of {@code dataTypeList} property
	 * 
	 * @return dataTypeList
	 */
	public List<String> getDataTypeList() {
		log.debug("Get  dataTypeList: " + dataTypeList);
		return dataTypeList;
	}

	/**
	 * Returns {@code FALSE} if an instance of the {@code Resource} is selected
	 * by the user otherwise TRUE.
	 * 
	 * @return attrbtn
	 */
	public boolean isAttrbtn() {
		log.debug("Get  attrbtn: " + attrbtn);
		return attrbtn;
	}

	/**
	 * Returns {@code FALSE} if an instance of {@code ResourceAttribute} is
	 * selected by the user otherwise TRUE.
	 * 
	 * @return attrValuebtn
	 */
	public boolean isAttrValuebtn() {
		log.debug("Get  attrValuebtn: " + attrValuebtn);
		return attrValuebtn;
	}

	/**
	 * Returns {@code FALSE} if a {@code Save} button was pressed otherwise
	 * {@code TRUE}.
	 * 
	 * @return operationFail
	 */
	public boolean isOperationFail() {
		log.debug("Get  operationFail: " + operationFail);
		return operationFail;
	}

	/**
	 * Returns the value of {@code newAttributeName} property
	 * 
	 * @return newAttributeName
	 */
	public String getNewAttributeName() {
		log.debug("Get  newAttributeName: " + newAttributeName);
		return newAttributeName;
	}

	/**
	 * Returns the value of {@code newAttributeValue} property
	 * 
	 * @return newAttributeValue
	 */
	public String getNewAttributeValue() {
		log.debug("Get  newAttributeValue: " + newAttributeValue);
		return newAttributeValue;
	}

	/**
	 * Returns the value of {@code selectedResourceAttributeValue} property
	 * 
	 * @return selectedResourceAttributeValue
	 */
	public ResAttrValues getSelectedResourceAttributeValue() {
		log.debug("Get  selectedResourceAttributeValue: "
				+ selectedResourceAttributeValue);
		return selectedResourceAttributeValue;
	}

	/**
	 * Returns the value of {@code daoResource} property
	 * 
	 * @return daoResource
	 */
	public ResourceDAO getDaoResource() {
		log.debug("Get  daoResource: " + daoResource);
		return daoResource;
	}

	/**
	 * Returns the value of {@code daoResourceAttribute } property
	 * 
	 * @return daoResourceAttribute
	 */
	public ResourceAttributeDAO getDaoResourceAttribute() {
		log.debug("Get  daoResourceAttribute: " + daoResourceAttribute);
		return daoResourceAttribute;
	}

	/**
	 * Returns the value of {@code daoResourceAttributeValue} property
	 * 
	 * @return daoResourceAttributeValue
	 */
	public ResAttrValuesDAO getDaoResourceAttributeValue() {
		log.debug("Get  daoResourceAttributeValue: "
				+ daoResourceAttributeValue);
		return daoResourceAttributeValue;
	}

	/**
	 * Returns the value of {@code selectedResource} property
	 * 
	 * @return selectedResource
	 */
	public Resource getSelectedResource() {

		log.debug("Get  selectedResource: " + selectedResource);
		return selectedResource;

	}

	/**
	 * Returns the {@code ArrayList} of {@code Resource} instances available.
	 * 
	 * @return ResourceList
	 */
	public ArrayList<Resource> getResourceList() {
		log.debug("Getting  resourceList ");
		return (ArrayList<Resource>) daoResource.selectResource();
	}

	/**
	 * Returns the value of {@code ResourceAttributeList } property
	 * corresponding to the {@code selectedResource}
	 * 
	 * @return ResourceAttributeList
	 */
	public ArrayList<ResourceAttribute> getResourceAttributeList() {
		if (this.selectedResource != null) {
			log.debug("Getting  resourceAttributeList ");
			return (ArrayList<ResourceAttribute>) daoResourceAttribute
					.selectResourceAttributes(selectedResource.getPkResource());
		}
		log.debug("Get  resourceAttributeList: " + resourceAttributeList);
		return this.resourceAttributeList;

	}

	/**
	 * Returns the value of {@code selectedResourceAttributes} property
	 * 
	 * @return selectedResourceAttributes
	 */
	public ResourceAttribute getSelectedResourceAttributes() {
		log.debug("Get  selectedResourceAttributes: "
				+ selectedResourceAttributes);
		return selectedResourceAttributes;
	}

	/**
	 * Returns the value of {@code ResourceAttributeValueList} property
	 * 
	 * @return ResourceAttributeValueList
	 */
	public ArrayList<ResAttrValues> getResourceAttributeValueList() {

		if (this.selectedResourceAttributes != null) {
			log.debug("Getting  resourceAttributeValueList ");
			return (ArrayList<ResAttrValues>) new ResAttrValuesDAO()
					.populateResValueList(selectedResourceAttributes
							.getPkResAttr());
		}
		log.debug("Get  resourceAttributeValueList: "
				+ resourceAttributeValueList);
		return this.resourceAttributeValueList;

	}

	/*-------------------------------------------------------------------------*/
	/*-------------------------------------------------------------------------*/
	/**
	 * Opens the {@code /System Learning/Resource/Add/AddResource.xhtml} page
	 * for creating a new {@code Resource} instance.
	 * 
	 * @return
	 */
	public void addResource() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 530);
		options.put("width", 1000);
		options.put("contentHeight", 520);
		options.put("contentWidth", 960);
		options.put("modal", true);
		log.info("Opening /System Learning/Resource/Add/AddResource in a dialog.");

		context.openDialog("/System Learning/Resource/Add/AddResource",
				options, null);

	}

	/**
	 * Opens the
	 * {@code /System Learning/Resource/Add/AddResourceAttributeValueDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of adding a new {@code ResAttrValues} instance
	 * corresponding to a @{code ResourceAttribute} of a {@code Resource}
	 * instance.
	 */
	public void addResourceAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 130);
		options.put("width", 580);
		options.put("contentHeight", 115);
		options.put("contentWidth", 565);
		options.put("modal", true);
		log.info("Opening /System Learning/Resource/Add/AddResourceAttributeValueDialog in a dialog.");

		context.openDialog(
				"/System Learning/Resource/Add/AddResourceAttributeValueDialog",
				options, null);
		this.newAttributeValue = null;

	}

	/**
	 * Opens the
	 * {@code /System Learning/Resource/Add/AddResourceAttributeDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of adding a new instance of @{code ResourceAttribute}
	 * corresponding to an existing {@code Resource} instance.
	 */
	public void addResourceAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 250);
		options.put("width", 580);
		options.put("contentHeight", 230);
		options.put("contentWidth", 565);
		options.put("modal", true);
		log.info("Opening /System Learning/Resource/Add/AddResourceAttributeDialog in a dialog.");

		context.openDialog(
				"/System Learning/Resource/Add/AddResourceAttributeDialog",
				options, null);
		this.newAttributeName = null;

	}

	/*-------------------------------------------------------------------------*/
	/*-------------------------------------------------------------------------*/
	/**
	 * Opens the
	 * {@code /System Learning/Resource/Update/UpdateResourceDialog.xhtml} file
	 * in a Primefaces {@code  Dialog} component which offers the functionality
	 * of updating the name and description of an existing {@code Resource}
	 * instance.
	 */
	public void updateResource() {

		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 280);
		options.put("width", 600);
		options.put("contentHeight", 260);
		options.put("contentWidth", 580);
		options.put("modal", true);
		log.info("Opening /System Learning/Resource/Update/UpdateResourceDialog in a dialog.");

		context.openDialog(
				"/System Learning/Resource/Update/UpdateResourceDialog",
				options, null);
	}

	/**
	 * Opens the
	 * {@code /System Learning/Resource/Update/UpdateResourceAttributeDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating the existing {@code ResourceAttribute} of an
	 * {@code Resource} instance.
	 */
	public void updateResourceAttribute() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 130);
		options.put("width", 580);
		options.put("contentHeight", 115);
		options.put("contentWidth", 565);
		options.put("modal", true);
		log.info("Opening /System Learning/Resource/Update/UpdateResourceAttributeDialog in a dialog.");

		context.openDialog(
				"/System Learning/Resource/Update/UpdateResourceAttributeDialog",
				options, null);

	}

	/**
	 * Opens the
	 * {@code /System Learning/Resource/Update/UpdateResourceAttributeValueDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating the value of an existing @
	 * {@code ResAttrValues} corresponding to an @{code ResourceAttribute} of an
	 * {@code Resource} instance.
	 */

	public void updateResourceAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 130);
		options.put("width", 580);
		options.put("contentHeight", 115);
		options.put("contentWidth", 565);
		options.put("modal", true);
		log.info("Opening /System Learning/Resource/Update/UpdateResourceAttributeValueDialog in a dialog.");

		context.openDialog(
				"/System Learning/Resource/Update/UpdateResourceAttributeValueDialog",
				options, null);

	}

	/*-------------------------------------------------------------------------*/
	/*-------------------------------------------------------------------------*/
	/**
	 * Deletes an instance of {@code ResourceAttribute} stored in
	 * {@code selectedResourceAttributes} property
	 */
	public void deleteResourceAttribute() {

		this.daoResourceAttribute
				.deleteResourceAttribute(this.selectedResourceAttributes
						.getPkResAttr());
		log.info("Deleted Successfully.");
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));
		this.attrValuebtn = true;

	}

	/**
	 * Deletes the instance of {@code ResAttrValues} stored in
	 * {@code selectedResourceAttributeValue} property
	 */
	public void deleteResourceAttributeValue() {
		this.daoResourceAttributeValue
				.deleteResourceAttributeValue(this.selectedResourceAttributeValue
						.getPkResAttrVal());
		log.info("Deleted Successfully.");
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));

	}

	/**
	 * Deletes the instance of {@code Resource} stored in
	 * {@code selectedResource} property
	 */
	public void deleteResource() {
		this.daoResource.deleteResource(this.selectedResource.getPkResource());
		log.info("Deleted Successfully.");
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));
		this.attrbtn = true;
		this.attrValuebtn = true;

	}

	/*-------------------------------------------------------------------------*/
	/*-------------------------------------------------------------------------*/
	/**
	 * Saves the updated value of {@code selectedResourceAttributeValue}
	 * property in the database.
	 */
	public void saveUpdateResourceAttributeValue() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.selectedResourceAttributeValue.getResAttrValue() == null) {
			log.info("Opening /Misc/ValueWarning in a dialog.");

			context.openDialog("/Misc/ValueWarning");

			return;

		} else {
			this.daoResourceAttributeValue.updateResAttrValue(
					this.selectedResourceAttributeValue.getPkResAttrVal(),
					this.selectedResourceAttributeValue.getResAttrValue());
			FacesContext.getCurrentInstance().getExternalContext().getFlash()
					.setKeepMessages(true);
			log.info("Resource Attribute Value Updated Successfully.");
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(FacesMessage.SEVERITY_INFO,
							"Successful Execution",
							"Resource Attribute Value Updated Successfully."));
			log.info("Closing dialog.");
			context.closeDialog(this);

			this.setOperationFail(false);
			return;
		}

	}

	/**
	 * Saves the updated value of {@code selectedResourceAttributes} property in
	 * the database.
	 */
	public void saveUpdateResourceAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.selectedResourceAttributes.getResAttrId() == null) {
			log.info("Opening /Misc/NameWarning in a dialog.");

			context.openDialog("/Misc/NameWarning");

			return;

		} else {
			this.daoResourceAttribute.updateResourceAttr(
					this.selectedResourceAttributes.getPkResAttr(),
					this.selectedResourceAttributes.getResAttrId());
			log.info("Closing dialog.");
			context.closeDialog(this);

			this.setOperationFail(false);
			return;
		}

	}

	/**
	 * Saves the newly added instance of {@code ResourceAttribute}in the
	 * database corresponding to an existing {@code Resource} instance referred
	 * by {@code selectedResource}
	 */
	public void saveAddResourceAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.newAttributeName == null) {
			log.info("Opening /Misc/NameWarning in a dialog.");

			context.openDialog("/Misc/NameWarning");

			return;

		} else {
			this.daoResourceAttribute.createResourceAttrValue(
					this.selectedResource, this.newAttributeName,
					this.selectedDataType, this.newAttributeValue);

			log.info("Closing dialog.");
			context.closeDialog(this);
			log.info("Resource Attribute Added Successfull.");
			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Successful Execution",
					"Resource Attribute Added Successfull."));
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(FacesMessage.SEVERITY_INFO,
							"Successful Execution",
							"Resource Attribute Added Successfull."));
			this.newAttributeName = null;
			this.newAttributeValue = null;
			this.setOperationFail(false);
			this.selectedDataType = null;
			return;
		}

	}

	/**
	 * Saves the newly added instance of {@code ResAttrValues}in the database
	 * corresponding to an existing {@code ResourceAttribute} instance referred
	 * by {@code selectedResourceAttributes}
	 */
	public void saveAddResourceAttributeValue() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.newAttributeValue == null) {
			log.info("Opening /Misc/ValueWarning in a dialog.");
			context.openDialog("/Misc/ValueWarning");

			return;

		} else {
			this.daoResourceAttributeValue.createResAttrValue(
					this.selectedResourceAttributes, this.newAttributeValue);
			log.info("Closing dialog.");
			context.closeDialog(this);
			log.info("Resource Attribute Value Added Successfully.");
			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Successful Execution",
					"Resource Attribute Value Added Successfully."));

			this.newAttributeValue = null;
			this.setOperationFail(false);
			return;
		}

	}

	/**
	 * Saves the updated value of {@code selectedResource} property in the
	 * database.
	 */
	public void saveUpdateResource() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (this.selectedResource.getResourceName() == null) {
			log.info("Opening /Misc/NameWarning in a dialog.");
			context.openDialog("/Misc/NameWarning");
			return;

		} else {

			this.daoResource.updateResource(
					this.selectedResource.getPkResource(),
					this.selectedResource.getDescription(),
					this.selectedResource.getResourceName());
			log.info("Closing dialog.");
			context.closeDialog(this);

			log.info("Resource Updated Successfully.");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Successful Execution",
					"Resource Updated Successfully."));
			this.setOperationFail(false);
			return;
		}

	}

	/*-------------------------------------------------------------------------*/
	/*-------------------------------------------------------------------------*/

	/**
	 * Cancels the operation of updating an existing {@code Resource} instance.
	 */

	public void cancelUpdateResource() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");

		context.closeDialog(this);
	}

	/**
	 * Cancels the operation of adding a new {@code ResAttrValues} corresponding
	 * to an existing {@code ResourceAttribute} instance
	 */
	public void cancelAddResourceAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);
		this.newAttributeValue = null;

	}

	/**
	 * Cancels the operation of updating an existing {@code ResAttrValues}
	 * instance.
	 */
	public void cancelUpdateResourceAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);

	}

	/**
	 * Cancels the operation of updating an existing {@code ResourceAttribute}
	 * instance.
	 */
	public void cancelUpdateResourceAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);
	}

	/**
	 * Cancels the operation of adding an existing {@code ResourceAttribute}
	 * instance corresponding to an existing {@code Resource} instance.
	 */
	public void cancelAddResourceAttribute() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);
		this.newAttributeName = null;
		this.selectedDataType = null;

	}

	/*-------------------------------------------------------------------------*/
	/*-------------------------------------------------------------------------*/
	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful add operation.
	 */
	public void showAddMessage() {

		if (!isOperationFail()) {
			log.info("Added Successfully.");
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Successfully"));
			this.setOperationFail(true);
		}

	}

	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful update operation.
	 */
	public void showUpdateMessage() {

		if (!isOperationFail()) {
			log.info("Updated Successfully.");
			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Updated Successfully"));

			this.setOperationFail(true);
		}

	}

	/*-------------------------------------------------------------------------*/
	/*-------------------------------------------------------------------------*/

	/**
	 * Disables the buttons for adding {@code ResourceAttribute} and
	 * {@code ResAttrValues} instances corresponding to an existing
	 * {@code Resource} instance.
	 */
	public void onResourceUnSelect() {
		this.attrbtn = true;
		this.attrValuebtn = true;
	}

	/**
	 * Disables the button for adding {@code ResAttrValues} instance
	 * corresponding to an existing {@code ResourceAttribute} instance.
	 */
	public void onResourceAttributeUnSelect() {
		this.attrValuebtn = true;
	}

	/**
	 * Disables the button for adding {@code ResAttrValues} instance and enables
	 * the button for adding {@code ResourceAttribute} instance whenever an
	 * {@code Resource} instance is selected.
	 */
	public void onResourceSelect() {
		this.attrbtn = false;
		this.attrValuebtn = true;
	}

}
