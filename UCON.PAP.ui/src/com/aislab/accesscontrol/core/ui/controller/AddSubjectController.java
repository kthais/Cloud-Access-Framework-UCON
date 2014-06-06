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

import com.aislab.accesscontrol.core.entities.SubAttrValues;
import com.aislab.accesscontrol.core.entities.Subject;
import com.aislab.accesscontrol.core.entities.SubjectAttribute;
import com.aislab.accesscontrol.core.ui.dao.SubjectDAO;

/**
 * A session scoped, managed bean for user interfaces related to adding a new
 * {@code Subject} instance
 * 
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 * 
 * 
 * 
 */
@ManagedBean
@SessionScoped
public class AddSubjectController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(AddSubjectController.class.getName());

	/**
	 * A String variable to store the value of {@code subjectName} attribute of
	 * {@code Subject} instance to be added.
	 */
	String name;
	/**
	 * A String variable to store the value of {@code description} attribute of
	 * {@code Subject} instance to be added.
	 */
	String description;
	/**
	 * A {@code List} of {@code String} representing the available subject
	 * categories corresponding to the {@code Subject} instance that is to be
	 * created.
	 */
	List<String> categoryList = Arrays.asList("Access Subject", "Code Base",
			"Intermediary Subject", "Recipient Subject", "Requesting Machine");
	/**
	 * A String variable to store the value of {@code subjectCategory} attribute
	 * of {@code Subject} instance that is to be created.
	 */

	String selectedCategory;
	/**
	 * A String variable to store the value of {@code subjAttrId} attribute of
	 * {@code SubjectAttribute} instance corresponding to the {@code Subject}
	 * instance to be added.
	 */
	String attributeName;
	/**
	 * A String variable to store the value of {@code subAttrValue} attribute of
	 * {@code SubAttrValues} instance corresponding to a newly created instance
	 * of {@code SubjectAttribute}.
	 */

	String attributeValueDefault;
	/**
	 * A String variable to store the value of {@code subAttrValue} attribute of
	 * any additional {@code SubAttrValues} instances corresponding to a newly
	 * created instance of {@code SubjectAttribute}.
	 */
	String attributeValue = null;
	/**
	 * An instance of {@code SubjectDAO} for using methods to access data
	 * related to {@code Subject}
	 */
	SubjectDAO daoSubject = new SubjectDAO();
	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed while adding a new {@code Subject},
	 * {@code SubjectAttribute} or {@code SubAttrValues} instance. By default it
	 * is set to {@code TRUE} while it is becomes {@code FALSE} if {@code Save}
	 * is pressed.
	 * 
	 */
	boolean operationFail = true;
	/**
	 * A String variable to store the value of {@code dataType} attribute of
	 * {@code SubjectAttribute} while adding a new {@code SubjectAttribute}
	 * corresponding to the {@code Subject} instance that is to be created.
	 */
	String selectedDataType = null;
	/**
	 * A {@code List} of {@code String} representing the available data types
	 * for adding a new {@code SubjectAttribute} corresponding to the
	 * {@code Subject} instance that is to be created.
	 */
	List<String> dataTypeList = Arrays.asList("String", "Integer", "Boolean",
			"anyURI");

	/**
	 * An ArrayList of {@code SubjectAttribute} used to display all the
	 * {@code SubjectAttribute}(s) newly created related to the new
	 * {@code Subject} instance that is to be created.
	 */
	public ArrayList<SubjectAttribute> subjectAttributeList = new ArrayList<SubjectAttribute>();
	/**
	 * An instance of {@code SubjectAttribute} used to store the
	 * {@code SubjectAttribute} selected by the user from the user interface.
	 */
	public SubjectAttribute selectedSubjectAttribute;
	/**
	 * A newly created instance of {@code Subject} that is to be added in the
	 * database
	 */
	public Subject subject = new Subject();
	/**
	 * A instance of {@code SubjectAttribute} used to store the relevant data
	 * when the user chooses to add a new {@code SubjectAttribute} instance.
	 */
	public SubjectAttribute attribute = new SubjectAttribute();
	/**
	 * A instance of {@code SubAttrValues} used to store the relevant data when
	 * the user chooses to add a new {@code SubAttrValues} instance.
	 */
	public SubAttrValues value = new SubAttrValues();
	/**
	 * An {@code ArrayList} of {@code SubAttrValues} instances used to display
	 * the already added instances of {@code SubAttrValues} corresponding to the
	 * {@code SubjectAttribute} selected by the user.
	 */
	public ArrayList<SubAttrValues> subjectAttributeValueList = new ArrayList<SubAttrValues>();
	/**
	 * An {@code ArrayList} of {@code SubAttrValues} instances used to add
	 * additional {@code SubAttrValues} instances to an instance of
	 * {@code SubjectAttribute}.
	 */
	public ArrayList<SubAttrValues> selectedAttributeValueList = new ArrayList<SubAttrValues>();

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
	 * Sets the {@code subjectAttributeList} property to the {@code  ArrayList}
	 * argument.
	 * 
	 * @param subjectAttributeList
	 */
	public void setSubjectAttributeList(
			ArrayList<SubjectAttribute> subjectAttributeList) {
		this.subjectAttributeList = subjectAttributeList;
		log.debug("Set  subjectAttributeList: " + subjectAttributeList);

	}

	/**
	 * Sets the {@code selectedSubjectAttribute} property to the
	 * {@code SubjectAttribute} argument.
	 * 
	 * @param selectedSubjectAttribute
	 */
	public void setSelectedSubjectAttribute(
			SubjectAttribute selectedSubjectAttribute) {
		this.selectedSubjectAttribute = selectedSubjectAttribute;
		log.debug("Set  selectedSubjectAttribute: " + selectedSubjectAttribute);

	}

	/**
	 * Sets the {@code attribute} property to the {@code SubjectAttribute}
	 * argument.
	 * 
	 * @param attribute
	 */
	public void setAttribute(SubjectAttribute attribute) {
		this.attribute = attribute;
		log.debug("Set  attribute: " + attribute);

	}

	/**
	 * Sets the {@code value} property to the {@code SubAttrValues} argument.
	 * 
	 * @param value
	 */
	public void setValue(SubAttrValues value) {
		this.value = value;
		log.debug("Set  value: " + value);

	}

	/**
	 * Sets the {@code subjectAttributeValueList} property to the
	 * {@code ArrayList} argument.
	 * 
	 * @param subjectAttributeValueList
	 */
	public void setSubjectAttributeValueList(
			ArrayList<SubAttrValues> subjectAttributeValueList) {
		this.subjectAttributeValueList = subjectAttributeValueList;
		log.debug("Set  subjectAttributeValueList: "
				+ subjectAttributeValueList);

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
	 * Sets the {@code daoSubject} property to {@code SubjectDAO} argument.
	 * 
	 * @param daoSubject
	 */
	public void setDaoSubject(SubjectDAO daoSubject) {
		this.daoSubject = daoSubject;
		log.debug("Set  daoSubject: " + daoSubject);
	}

	/**
	 * Sets the {@code subject} property to the {@code Subject} argument.
	 * 
	 * @param subject
	 */
	public void setSubject(Subject subject) {
		this.subject = subject;
		log.debug("Set  subject: " + subject);
	}

	/**
	 * Sets the {@code selectedAttributeValueList} property to the
	 * {@code ArrayList} argument.
	 * 
	 * @param selectedAttributeValueList
	 */
	public void setSelectedAttributeValueList(
			ArrayList<SubAttrValues> selectedAttributeValueList) {
		this.selectedAttributeValueList = selectedAttributeValueList;
		log.debug("Set  selectedAttributeValueList: "
				+ selectedAttributeValueList);
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
	 * Sets the {@code selectedCategory} property to the {@code String}
	 * argument.
	 * 
	 * @param selectedCategory
	 */
	public void setSelectedCategory(String selectedCategory) {
		this.selectedCategory = selectedCategory;
		log.debug("Set  selectedCategory: " + selectedCategory);
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
	 * Sets the {@code categoryList} property to the {@code List} argument.
	 * 
	 * @param categoryList
	 */
	public void setCategoryList(List<String> categoryList) {
		this.categoryList = categoryList;
		log.debug("Set  categoryList: " + categoryList);

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
	 * Returns the value of {@code daoSubject} property.
	 * 
	 * @return daoSubject
	 */
	public SubjectDAO getDaoSubject() {
		log.debug("Get  daoSubject: " + daoSubject);
		return daoSubject;
	}

	/**
	 * Returns the value of {@code subject} property.
	 * 
	 * @return subject
	 */
	public Subject getSubject() {
		log.debug("Get  subject: " + subject);
		return subject;
	}

	/**
	 * Returns the value of {@code selectedAttributeValueList} property.
	 * 
	 * @return selectedAttributeValueList
	 */
	public ArrayList<SubAttrValues> getSelectedAttributeValueList() {
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
	 * Returns the value of {@code selectedCategory} property.
	 * 
	 * @return selectedCategory
	 */
	public String getSelectedCategory() {
		log.debug("Get  selectedCategory: " + selectedCategory);
		return selectedCategory;
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
	 * Returns the value of {@code categoryList} property.
	 * 
	 * @return categoryList
	 */
	public List<String> getCategoryList() {
		log.debug("Get  categoryList: " + categoryList);
		return categoryList;
	}

	/**
	 * Returns the value of {@code subjectAttributeList} property.
	 * 
	 * @return subjectAttributeList
	 */
	public ArrayList<SubjectAttribute> getSubjectAttributeList() {
		log.debug("Get  subjectAttributeList: " + subjectAttributeList);
		return subjectAttributeList;
	}

	/**
	 * Returns the value of {@code selectedSubjectAttribute} property.
	 * 
	 * @return selectedSubjectAttribute
	 */
	public SubjectAttribute getSelectedSubjectAttribute() {
		log.debug("Get  selectedSubjectAttribute: " + selectedSubjectAttribute);
		return selectedSubjectAttribute;
	}

	/**
	 * Returns the value of {@code attribute} property.
	 * 
	 * @return attribute
	 */
	public SubjectAttribute getAttribute() {
		log.debug("Get  attribute: " + attribute);
		return attribute;
	}

	/**
	 * Returns the value of {@code value} property.
	 * 
	 * @return value
	 */
	public SubAttrValues getValue() {
		log.debug("Get  value: " + value);
		return value;
	}

	/**
	 * Returns the value of {@code subjectAttributeValueList} property.
	 * 
	 * @return subjectAttributeValueList
	 */
	public ArrayList<SubAttrValues> getSubjectAttributeValueList() {
		if (this.selectedSubjectAttribute != null) {
			this.subjectAttributeValueList = new ArrayList<>(
					this.selectedSubjectAttribute.getSubAttrValues());

		}
		log.debug("Get  subjectAttributeValueList: "
				+ subjectAttributeValueList);
		return this.subjectAttributeValueList;
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
	 * {@code SubjectAttribute} instance.
	 */

	public void addSubjectAttribute() {
		this.attributeName = null;
		this.attributeValueDefault = null;
		this.value = null;
		this.selectedAttributeValueList = null;
		this.attribute = null;
		this.selectedDataType = null;

	}

	/**
	 * Opens a {@code p:dialog} component for creating a new
	 * {@code SubAttrValues} instance.
	 */
	public void addSubjectAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();

		if (this.selectedSubjectAttribute == null) {
			log.info("No Attribute Selected. Please Select  Attribute  First.");

			context.showMessageInDialog(new FacesMessage("Warning",
					"No Attribute Selected. Please Select  Attribute  First."));

		} else {

			this.attributeName = null;
			this.attributeValue = null;
			this.value = null;

			context.execute("PF('ex1').show()");

		}

	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/**
	 * 
	 * Saves the newly created instance of {@code Subject} in the database.
	 * 
	 * @return
	 */
	public String saveSubject() {

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

		if (this.selectedCategory == null
				|| this.selectedCategory.equals("Select Category")) {
			log.info("Category must be selected.");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Category must be selected."));

			return null;
		}

		if (this.subjectAttributeList.isEmpty()) {
			log.info("Subject must have a Attribute(s).");

			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Warning",
					"Subject must have a Attribute(s)."));

			return null;
		} else {
			if ((!this.subjectAttributeList.isEmpty())) {
				// System.out.println("checking");
			}

			this.daoSubject.createSubject(this.description, this.name,
					this.selectedCategory, this.subjectAttributeList);

			this.attribute = null;
			this.name = null;
			this.description = null;
			this.selectedCategory = null;
			this.subjectAttributeList.clear();
			this.selectedAttributeValueList = null;
			this.selectedSubjectAttribute = null;
			this.selectedDataType = null;

			this.subjectAttributeValueList.clear();
			log.info("Subject Added Successfully");

			context.showMessageInDialog(new FacesMessage(
					" Successful Execution", "Subject Added Successfully"));
			FacesContext.getCurrentInstance().getExternalContext().getFlash()
					.put("addFail", false);
			FacesContext.getCurrentInstance().getExternalContext().getFlash()
					.setKeepMessages(true);
			log.info("Closing dialog.");

			context.closeDialog(this);

			this.operationFail = false;

			return null;
		}

	}

	/**
	 * Saves the newly created instance of {@code SubjectAttribute}
	 * corresponding to the {@code Subject} instance that is to be created.
	 */
	public void saveAddSubjectAttribute() {
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
			this.attribute = new SubjectAttribute();
			this.value = new SubAttrValues();
			this.selectedAttributeValueList = new ArrayList<SubAttrValues>();
			this.attribute.setSubjAttrId(this.attributeName);

			this.attribute
					.setDataType(this.selectedDataType != null ? this.selectedDataType
							: "String");

			this.value.setSubAttrValue(this.attributeValueDefault);
			this.selectedAttributeValueList.add(this.value);
			this.attribute.setSubAttrValues(new HashSet<SubAttrValues>(
					this.selectedAttributeValueList));
			this.subjectAttributeList.add(attribute);

			this.attributeName = null;
			this.attributeValueDefault = null;
			this.value = null;
			this.attribute = null;
			this.selectedAttributeValueList.clear();

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

	/**
	 * Saves the newly created instance of {@code SubAttrValues} corresponding
	 * to an instance of {@code SubjectAttribute}.
	 */
	public void saveAddSubjectAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();

		this.value = new SubAttrValues();
		this.value.setSubAttrValue(this.attributeValue);
		this.selectedSubjectAttribute.getSubAttrValues().add(this.value);

		this.attributeValue = null;
		this.value = null;

		context.execute("PF('ex1').hide()");

	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/**
	 * Cancels the operation of adding a new {@code Subject} instance in the
	 * database.
	 * 
	 * @return
	 */

	public void cancelSubject() {

		this.attribute = null;
		this.name = null;
		this.description = null;
		this.selectedCategory = null;
		this.subjectAttributeList.clear();
		this.selectedAttributeValueList = null;
		this.subjectAttributeValueList.clear();
		this.selectedSubjectAttribute = null;
		FacesContext.getCurrentInstance().getExternalContext().getFlash()
				.put("addFail", true);
		log.info("Subject Updated Successfully");

		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Subject Updated Successfully" + this.attributeValue));

		this.operationFail = true;

		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);
	}

	/**
	 * Cancels the operation of adding a new {@code SubjectAttribute} instance.
	 */
	public void cancelAddSubjectAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();

		this.attributeName = null;
		this.attributeValueDefault = null;
		this.selectedDataType = null;

		context.execute("PF('ex').hide()");

	}

	/**
	 * Cancels the operation of adding a new {@code SubAttrValues} instance.
	 */
	public void cancelAddSubjectAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		context.execute("PF('ex1').hide()");
		this.attributeValue = null;

	}

	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/*-----------------------------------------------------------------------------------------------------------------------------*/
	/**
	 * Displays a message inside a Primefaces {@code growl} component in case of
	 * successful add operation.
	 */
	public void showAddMessage() {

		if (!isOperationFail()) {
			log.info("Added Subject Successfully.");

			FacesContext.getCurrentInstance().addMessage(
					null,
					new FacesMessage(" Successful Execution",
							"Added Subject Successfully"));

			this.setOperationFail(true);
		}

	}

}
