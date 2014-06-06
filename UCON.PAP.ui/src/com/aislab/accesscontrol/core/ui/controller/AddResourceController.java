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
import java.util.HashSet;
import java.util.List;

import javax.faces.application.FacesMessage;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.primefaces.context.RequestContext;

import com.aislab.accesscontrol.core.entities.ResAttrValues;
import com.aislab.accesscontrol.core.entities.Resource;
import com.aislab.accesscontrol.core.entities.ResourceAttribute;
import com.aislab.accesscontrol.core.ui.dao.ResourceDAO;

/**
 * A session scoped, managed bean for user interfaces related to adding a new
 * {@code Resource} instance
 * 
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 */
@ManagedBean
@SessionScoped
public class AddResourceController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(AddResourceController.class.getName());

	/**
	 * A String variable to store the value of {@code resourceName} attribute of
	 * {@code Resource} instance to be added.
	 */
	String name;
	/**
	 * A String variable to store the value of {@code description} attribute of
	 * {@code Resource} instance to be added.
	 */

	String description;
	/**
	 * A String variable to store the value of {@code resAttrId} attribute of
	 * {@code ResourceAttribute} instance corresponding to the {@code Resource}
	 * instance to be added.
	 */
	String attributeName;
	/**
	 * A String variable to store the value of {@code resAttrValue} attribute of
	 * {@code ResAttrValues} instance corresponding to a newly created instance
	 * of {@code ResourceAttribute}.
	 */
	String attributeValueDefault;
	/**
	 * A String variable to store the value of {@code resAttrValue} attribute of
	 * any additional {@code ResAttrValues} instances corresponding to a newly
	 * created instance of {@code ResourceAttribute}.
	 */
	String attributeValue = null;
	/**
	 * An instance of {@code ResourceDAO} for using methods to access data
	 * related to {@code Resource}
	 */
	ResourceDAO daoResource = new ResourceDAO();
	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed while adding a new {@code Resource},
	 * {@code ResourceAttribute} or {@code ResAttrValues} instance. By default
	 * it is set to {@code TRUE} while it is becomes {@code FALSE} if
	 * {@code Save} is pressed.
	 * 
	 */
	boolean operationFail = true;
	/**
	 * An ArrayList of {@code ResourceAttribute} used to display all the
	 * {@code ResourceAttribute}(s) newly created related to the new
	 * {@code Resource} instance that is to be created.
	 */
	public ArrayList<ResourceAttribute> resourceAttributeList = new ArrayList<ResourceAttribute>();
	/**
	 * An instance of {@code ResourceAttribute} used to store the
	 * {@code ResourceAttribute} selected by the user from the user interface.
	 */
	public ResourceAttribute selectedResourceAttribute;
	/**
	 * A newly created instance of {@code Resource} that is to be added in the
	 * database
	 */
	public Resource resource = new Resource();
	/**
	 * A instance of {@code ResourceAttribute} used to store the relevant data
	 * when the user chooses to add a new {@code ResourceAttribute} instance.
	 */
	public ResourceAttribute attribute = new ResourceAttribute();
	/**
	 * A instance of {@code ResAttrValues} used to store the relevant data when
	 * the user chooses to add a new {@code ResAttrValues} instance.
	 */
	public ResAttrValues value = new ResAttrValues();
	/**
	 * An {@code ArrayList} of {@code ResAttrValues} instances used to display
	 * the already added instances of {@code ResAttrValues} corresponding to the
	 * {@code ResourceAttribute} selected by the user.
	 */
	public ArrayList<ResAttrValues> resourceAttributeValueList = new ArrayList<ResAttrValues>();
	/**
	 * An {@code ArrayList} of {@code ResAttrValues} instances used to add
	 * additional {@code ResAttrValues} instances to an instance of
	 * {@code ResourceAttribute}.
	 */

	public ArrayList<ResAttrValues> selectedAttributeValueList = new ArrayList<ResAttrValues>();

	/**
	 * A String variable to store the value of {@code dataType} attribute of
	 * {@code ResourceAttribute} while adding a new {@code ResourceAttribute}
	 * corresponding to the {@code Resource} instance that is to be created.
	 */
	String selectedDataType = null;
	/**
	 * A {@code List} of {@code String} representing the available data types
	 * for adding a new {@code ResourceAttribute} corresponding to the
	 * {@code Resource} instance that is to be created.
	 */
	List<String> dataTypeList = Arrays.asList("String", "Integer", "Boolean",
			"anyURI");

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/

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
	 * Sets the {@code name} property to the {@code String} argument.
	 * 
	 * @param name
	 */
	public void setName(String name) {
		this.name = name;
		log.debug("Set  name: " + name);

	}

	/**
	 * Sets the {@code description} property to the {@code String} argument.
	 * 
	 * @param description
	 */

	public void setDescription(String description) {
		this.description = description;
		log.debug("Set  description: " + description);
	}

	/**
	 * Sets the {@code resourceAttributeList} property to the {@code  ArrayList}
	 * argument.
	 * 
	 * @param resourceAttributeList
	 */
	public void setResourceAttributeList(
			ArrayList<ResourceAttribute> resourceAttributeList) {
		this.resourceAttributeList = resourceAttributeList;
		log.debug("Set  resourceAttributeList: " + resourceAttributeList);

	}

	/**
	 * Sets the {@code selectedResourceAttribute} property to the
	 * {@code ResourceAttribute} argument.
	 * 
	 * @param selectedResourceAttribute
	 */

	public void setSelectedResourceAttribute(
			ResourceAttribute selectedResourceAttribute) {
		this.selectedResourceAttribute = selectedResourceAttribute;
		log.debug("Set  selectedResourceAttribute: "
				+ selectedResourceAttribute);

	}

	/**
	 * Sets the {@code attribute} property to the {@code ResourceAttribute}
	 * argument.
	 * 
	 * @param attribute
	 */
	public void setAttribute(ResourceAttribute attribute) {
		this.attribute = attribute;
		log.debug("Set  attribute: " + attribute);

	}

	/**
	 * Sets the {@code value} property to the {@code ResAttrValues} argument.
	 * 
	 * @param value
	 */
	public void setValue(ResAttrValues value) {
		this.value = value;
		log.debug("Set  value: " + value);

	}

	/**
	 * Sets the {@code resourceAttributeValueList} property to the
	 * {@code ArrayList} argument.
	 * 
	 * @param resourceAttributeValueList
	 */
	public void setResourceAttributeValueList(
			ArrayList<ResAttrValues> resourceAttributeValueList) {
		this.resourceAttributeValueList = resourceAttributeValueList;
		log.debug("Set  resourceAttributeValueList: "
				+ resourceAttributeValueList);

	}

	/**
	 * Sets the {@code selectedDataType} property to the {@code String}
	 * argument.
	 * 
	 * @param dataType
	 */

	public void setSelectedDataType(String dataType) {
		this.selectedDataType = dataType;
		log.debug("Set  selectedDataType: " + selectedDataType);
	}

	/**
	 * Sets the {@code dataTypeList} property to the {@code List} argument.
	 * 
	 * @param dataTypeList
	 */
	public void setDataTypeList(List<String> dataTypeList) {
		this.dataTypeList = dataTypeList;
		log.debug("Set  dataTypeList: " + dataTypeList);
	}

	/**
	 * Sets the {@code attributeValueDefault} property to the {@code String}
	 * argument.
	 * 
	 * @param attributeValueDefault
	 */
	public void setAttributeValueDefault(String attributeValueDefault) {
		this.attributeValueDefault = attributeValueDefault;
		log.debug("Set  attributeValueDefault: " + attributeValueDefault);
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
	 * Sets the {@code resource} property to the {@code Resource} argument.
	 * 
	 * @param resource
	 */
	public void setResource(Resource resource) {
		this.resource = resource;
		log.debug("Set  resource: " + resource);
	}

	/**
	 * Sets the {@code selectedAttributeValueList} property to the
	 * {@code ArrayList} argument.
	 * 
	 * @param selectedAttributeValueList
	 */

	public void setSelectedAttributeValueList(
			ArrayList<ResAttrValues> selectedAttributeValueList) {
		this.selectedAttributeValueList = selectedAttributeValueList;
		log.debug("Set  selectedAttributeValueList: "
				+ selectedAttributeValueList);
	}

	/**
	 * Sets the {@code attributeName} property to the {@code String} argument.
	 * 
	 * @param attributeName
	 */

	public void setAttributeName(String attributeName) {
		this.attributeName = attributeName;
		log.debug("Set  attributeName: " + attributeName);
	}

	/**
	 * Sets the {@code attributeValue} property to the {@code String} argument.
	 * 
	 * @param attributeValue
	 */
	public void setAttributeValue(String attributeValue) {
		this.attributeValue = attributeValue;
		log.debug("Set  attributeValue: " + attributeValue);
	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/

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
	 * Returns the value of {@code attributeValueDefault} property.
	 * 
	 * @return attributeValueDefault
	 */
	public String getAttributeValueDefault() {
		log.debug("Get  attributeValueDefault: " + attributeValueDefault);
		return attributeValueDefault;
	}

	/**
	 * Returns the value of {@code daoResource} property.
	 * 
	 * @return daoResource
	 */

	public ResourceDAO getDaoResource() {
		log.debug("Get  daoResource: " + daoResource);
		return daoResource;
	}

	/**
	 * Returns the value of {@code resource} property.
	 * 
	 * @return resource
	 */
	public Resource getResource() {
		log.debug("Get  resource: " + resource);
		return resource;
	}

	/**
	 * Returns the value of {@code selectedAttributeValueList} property.
	 * 
	 * @return selectedAttributeValueList
	 */
	public ArrayList<ResAttrValues> getSelectedAttributeValueList() {
		log.debug("Get  selectedAttributeValueList: "
				+ selectedAttributeValueList);
		return selectedAttributeValueList;
	}

	/**
	 * Returns the value of {@code attributeValue} property.
	 * 
	 * @return attributeValue
	 */
	public String getAttributeValue() {
		log.debug("Get  attributeValue: " + attributeValue);
		return attributeValue;
	}

	/**
	 * Returns the value of {@code attributeName} property.
	 * 
	 * @return attributeName
	 */
	public String getAttributeName() {

		log.debug("Get  attributeName: " + attributeName);
		return attributeName;
	}

	/**
	 * Returns the value of {@code name} property.
	 * 
	 * @return name
	 */
	public String getName() {
		log.debug("Get  name: " + name);
		return name;
	}

	/**
	 * Returns the value of {@code description} property.
	 * 
	 * @return description
	 */
	public String getDescription() {
		log.debug("Get  description: " + description);
		return description;
	}

	/**
	 * Returns the value of {@code resourceAttributeList} property.
	 * 
	 * @return resourceAttributeList
	 */
	public ArrayList<ResourceAttribute> getResourceAttributeList() {
		log.debug("Get  resourceAttributeList: " + resourceAttributeList);
		return resourceAttributeList;
	}

	/**
	 * Returns the value of {@code selectedResourceAttribute} property.
	 * 
	 * @return selectedResourceAttribute
	 */
	public ResourceAttribute getSelectedResourceAttribute() {
		log.debug("Get  selectedResourceAttribute: "
				+ selectedResourceAttribute);
		return selectedResourceAttribute;
	}

	/**
	 * Returns the value of {@code attribute} property.
	 * 
	 * @return attribute
	 */
	public ResourceAttribute getAttribute() {
		log.debug("Get  attribute: " + attribute);
		return attribute;
	}

	/**
	 * Returns the value of {@code value} property.
	 * 
	 * @return value
	 */
	public ResAttrValues getValue() {
		log.debug("Get  value: " + value);
		return value;
	}

	/**
	 * Returns the value of {@code resourceAttributeValueList} property.
	 * 
	 * @return resourceAttributeValueList
	 */
	public ArrayList<ResAttrValues> getResourceAttributeValueList() {
		if (this.selectedResourceAttribute != null) {
			this.resourceAttributeValueList = new ArrayList<>(
					this.selectedResourceAttribute.getResAttrValues());

		}
		log.debug("Get  resourceAttributeValueList: "
				+ resourceAttributeValueList);
		return this.resourceAttributeValueList;
	}

	/**
	 * Returns the value of {@code selectedDataType} property.
	 * 
	 * @return selectedDataType
	 */

	public String getSelectedDataType() {
		log.debug("Get  selectedDataType: " + selectedDataType);
		return this.selectedDataType;

	}

	/**
	 * Returns the value of {@code dataTypeList} property.
	 * 
	 * @return dataTypeList
	 */
	public List<String> getDataTypeList() {
		log.debug("Get  dataTypeList: " + dataTypeList);
		return this.dataTypeList;
	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/**
	 * Opens a {@code p:dialog} component for creating a new
	 * {@code ResourceAttribute} instance.
	 */
	public void addResourceAttribute() {
		this.attributeName = null;
		this.attributeValueDefault = null;
		this.value = null;
		this.selectedAttributeValueList = null;
		this.attribute = null;
		this.selectedDataType = null;

		RequestContext context = RequestContext.getCurrentInstance();

		context.execute("PF('ex').show()");

	}

	/**
	 * Opens a {@code p:dialog} component for creating a new
	 * {@code ResAttrValues} instance.
	 */
	public void addResourceAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();

		if (this.selectedResourceAttribute == null) {
			log.info("No Attribute Selected. Please Select  Attribute  First.");

			context.showMessageInDialog(new FacesMessage("Warning",
					"No Attribute Selected. Please Select  Attribute  First."));

		} else {
			this.attributeName = null;
			this.attributeValue = null;
			this.value = null;
			this.selectedDataType = null;
			this.selectedAttributeValueList = null;

			context.execute("PF('ex1').show()");
		}

	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/**
	 * 
	 * Saves the newly created instance of {@code Resource} in the database.
	 * 
	 * @return
	 */
	public String saveResource() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.name == null) {
			log.info("Name cannot be empty.");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Name cannot be empty."));

			return null;
		}

		if (this.description == null) {
			log.info("Description cannot be empty.");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Description cannot be empty."));

			return null;
		}

		if (this.resourceAttributeList.isEmpty()) {
			log.info("Resource must have a Attribute(s).");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Resource must have a Attribute(s)."));

			return null;
		} else {
			if ((!this.resourceAttributeList.isEmpty())) {
				// System.out.println("checking");
			}

			this.daoResource.createResource(this.description, this.name,
					this.resourceAttributeList);

			this.attribute = null;
			this.name = null;
			this.description = null;
			this.resourceAttributeList.clear();
			this.selectedAttributeValueList = null;
			this.resourceAttributeValueList = null;
			this.selectedResourceAttribute = null;
			log.info("Resource Added Successfully");

			context.showMessageInDialog(new FacesMessage(
					" Successful Execution", "Resource Added Successfully"));
			log.info("Closing dialog.");

			context.closeDialog(this);

			this.operationFail = false;

			return null;
		}

	}

	/**
	 * Saves the newly created instance of {@code ResAttrValues} corresponding
	 * to an instance of {@code ResourceAttribute}.
	 */
	public void saveAddResourceAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		this.value = new ResAttrValues();
		this.value.setResAttrValue(this.attributeValue);
		this.selectedResourceAttribute.getResAttrValues().add(this.value);

		this.attributeValue = null;
		this.value = null;
		context.execute("PF('ex1').hide()");
	}

	/**
	 * Saves the newly created instance of {@code ResourceAttribute}
	 * corresponding to the {@code Resource} instance that is to be created.
	 */
	public void saveAddResourceAttribute() {
		RequestContext context = RequestContext.getCurrentInstance();

		if (this.attributeName == null) {
			context.execute("noNameDialog.show()");
			return;

		}

		if (this.attributeValueDefault == null) {
			context.execute("noValueDialog.show()");
			return;

		}
		if (this.attributeName != null && this.attributeValueDefault != null) {
			this.attribute = new ResourceAttribute();
			this.value = new ResAttrValues();
			this.selectedAttributeValueList = new ArrayList<ResAttrValues>();
			this.attribute.setResAttrId(this.attributeName);

			this.attribute
					.setDataType(this.selectedDataType != null ? this.selectedDataType
							: "String");

			this.value.setResAttrValue(this.attributeValueDefault);
			this.selectedAttributeValueList.add(this.value);
			this.attribute.setResAttrValues(new HashSet<ResAttrValues>(
					this.selectedAttributeValueList));
			this.resourceAttributeList.add(attribute);

			this.attributeName = null;
			this.attributeValueDefault = null;
			this.value = null;
			this.attribute = null;
		}

		this.attributeName = null;
		this.attributeValueDefault = null;
		this.attributeName = null;
		this.value = null;
		this.attribute = null;
		this.selectedAttributeValueList = null;
		this.selectedDataType = null;

		context.execute("PF('ex').hide()");

	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/**
	 * Cancels the operation of adding a new {@code Resource} instance in the
	 * database.
	 * 
	 * @return
	 */
	public String cancelResource() {

		this.attribute = null;
		this.name = null;
		this.description = null;
		this.resourceAttributeList.clear();
		this.selectedAttributeValueList = null;
		this.resourceAttributeValueList = null;
		this.selectedResourceAttribute = null;

		this.operationFail = true;

		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);

		return null;

	}

	/**
	 * Cancels the operation of adding a new {@code ResourceAttribute} instance.
	 */
	public void cancelAddResourceAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();
		this.attributeName = null;
		this.attributeValueDefault = null;
		this.selectedDataType = null;

		context.execute("PF('ex').hide()");

	}

	/**
	 * Cancels the operation of adding a new {@code ResAttrValues} instance.
	 */
	public void cancelAddResourceAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		this.attributeValue = null;

		context.execute("PF('ex1').hide()");

	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful add operation.
	 */
	public void showAddMessage() {

		if (!isOperationFail()) {
			log.info("Added Resource Successfully");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Resource Successfully"));

			this.setOperationFail(true);
		}

	}

}
