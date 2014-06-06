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

import com.aislab.accesscontrol.core.entities.SubAttrValues;
import com.aislab.accesscontrol.core.entities.Subject;
import com.aislab.accesscontrol.core.entities.SubjectAttribute;
import com.aislab.accesscontrol.core.ui.dao.SubAttrValuesDAO;
import com.aislab.accesscontrol.core.ui.dao.SubjectAttributeDAO;
import com.aislab.accesscontrol.core.ui.dao.SubjectDAO;

/**
 * A session scoped, managed bean for user interfaces related to {@code Subject}
 * 
 * @author Arjumand Fatima <09bicseafatima@seecs.edu.pk>
 * @version 1.0
 * 
 * 
 * 
 */
@ManagedBean
@SessionScoped
public class SubjectController {
	/**
	 * A static {@code Logger} instance for logging
	 */
	static Logger log = Logger.getLogger(SubjectController.class.getName());

	/**
	 * A boolean variable to check whether the {@code Save} or {@code Cancel}
	 * button was pressed in a modification operation. By default it is set to
	 * {@code TRUE} while it is becomes {@code FALSE} if {@code Save} is
	 * pressed.
	 * 
	 */
	boolean operationFail = true;

	/**
	 * A String variable to store the value of {@code subAttrId} attribute of
	 * {@code SubjectAttribute} while adding a new {@code SubjectAttribute}
	 * corresponding to an existing {@code Subject} instance.
	 */
	String newAttributeName = null;
	/**
	 * A String variable to store the value of {@code subAttrValue} attribute of
	 * {@code SubAttrValues} while adding a new {@code SubjectAttribute}
	 * corresponding to an existing {@code Subject} instance.
	 */
	String newAttributeValue = null;
	// String name = null;

	/**
	 * A boolean variable to check whether any {@code Subject} instance is
	 * selected by the user so that the corresponding {@code SubjectAttribute}
	 * instance can be added. By default it is set to {@code TRUE} so that the
	 * corresponding add button is disabled while it is becomes {@code FALSE} if
	 * any {@code Subject} instance is selected in the user interface.
	 */
	boolean attrbtn = true;
	/**
	 * A boolean variable to check whether any {@code SubjectAttribute} instance
	 * is selected by the user so that the corresponding {@code SubAttrValue}
	 * instance can be added. By default it is set to {@code TRUE} so that the
	 * corresponding add button is disabled while it is becomes {@code FALSE} if
	 * any {@code SubjectAttribute} instance is selected in the user interface.
	 */
	boolean attrValuebtn = true;
	/**
	 * A {@code List} of {@code String} representing the available subject
	 * categories corresponding to a {@code Subject} instance.
	 */
	List<String> categoryList = Arrays.asList("Access Subject", "Code Base",
			"Intermediary Subject", "Recipient Subject", "Requesting Machine");

	/**
	 * An instance of {@code SubjectDAO} for using methods to access data
	 * related to {@code Subject}
	 */

	SubjectDAO daoSubject = new SubjectDAO();
	/**
	 * An instance of {@code SubjectAttributeDAO} for using methods to access
	 * data related to {@code SubjectAttribute}
	 */
	SubjectAttributeDAO daoSubjectAttribute = new SubjectAttributeDAO();
	/**
	 * An instance of {@code SubAttrValuesDAO} for using methods to access data
	 * related to {@code SubAttrValues}
	 */
	SubAttrValuesDAO daoSubjectAttributeValue = new SubAttrValuesDAO();

	/**
	 * An instance of {@code Subject} used to store the {@code Subject} selected
	 * by the user from the user interface.
	 */

	public Subject selectedSubject;;
	/**
	 * An ArrayList of {@code Subject} used to display all the existing
	 * {@code Subject}s stored in the database.
	 */
	public ArrayList<Subject> subjectList = new ArrayList<Subject>();

	/**
	 * An ArrayList of {@code SubjectAttribute} used to display all the existing
	 * {@code SubjectAttribute}(s) stored in the database. These
	 * {@code SubjectAttribute}(s) are related to a particular {@code Subject}
	 * instance stored in {@code selectedSubject}.
	 */

	public ArrayList<SubjectAttribute> subjectAttributeList = new ArrayList<SubjectAttribute>();
	/**
	 * An instance of {@code SubjectAttribute} used to store the
	 * {@code SubjectAttribute} selected by the user from the user interface.
	 */
	public SubjectAttribute selectedSubjectAttributes;
	/**
	 * An ArrayList of {@code SubAttrValues} used to display all the existing
	 * {@code SubAttrValues}(s) stored in the database. These
	 * {@code SubAttrValues}(s) are related to a particular
	 * {@code SubjectAttribute} instance stored in
	 * {@code selectedSubjectAttributes}.
	 */
	public ArrayList<SubAttrValues> subjectAttributeValueList;
	/**
	 * An instance of {@code SubAttrValues} used to store the
	 * {@code SubAttrValues} selected by the user from the user interface.
	 */
	public SubAttrValues selectedSubjectAttributeValue;

	/**
	 * A String variable to store the value of {@code dataType} attribute of
	 * {@code SubjectAttribute} while adding a new {@code SubjectAttribute}
	 * corresponding to an exiting {@code Subject} instance.
	 */
	String selectedDataType = null;

	/**
	 * A {@code List} of {@code String} representing the available data types
	 * for adding a new {@code SubjectAttribute} corresponding to an exiting
	 * {@code Subject} instance.
	 */
	List<String> dataTypeList = Arrays.asList("String", "Integer", "Boolean",
			"anyURI");

	/*--------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------*/
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
	 * Sets the {@code dataTypeList} property to {@code List} argument
	 * 
	 * @param dataTypeList
	 */
	public void setDataTypeList(List<String> dataTypeList) {
		this.dataTypeList = dataTypeList;
		log.debug("Set  dataTypeList: " + dataTypeList);
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
	 * Sets the {@code attrbtn} property to {@code boolean} argument.
	 * 
	 * @param attrbtn
	 */
	public void setAttrbtn(boolean attrbtn) {
		this.attrbtn = attrbtn;
		log.debug("Set  attrbtn: " + attrbtn);
	}

	/**
	 * Sets the {@code attrValuebtn} property to {@code boolean} argument.
	 * 
	 * @param attrValuebtn
	 */
	public void setAttrValuebtn(boolean attrValuebtn) {
		this.attrValuebtn = attrValuebtn;
		log.debug("Set  attrValuebtn: " + attrValuebtn);
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
	 * Sets the {@code newAttributeValue} property to {@code String} argument.
	 * 
	 * @param newAttributeValue
	 */

	public void setNewAttributeValue(String newAttributeValue) {
		this.newAttributeValue = newAttributeValue;
		log.debug("Set  newAttributeValue: " + newAttributeValue);
	}

	/**
	 * Sets the {@code categoryList} property to {@code List} argument
	 * 
	 * @param categoryList
	 */
	public void setCategoryList(List<String> categoryList) {
		this.categoryList = categoryList;
		log.debug("Set  categoryList: " + categoryList);
	}

	/**
	 * Sets the {@code selectedSubjectAttributeValue} property to
	 * {@code SubAttrValues} argument.
	 * 
	 * @param selectedSubjectAttributeValue
	 */
	public void setSelectedSubjectAttributeValue(
			SubAttrValues selectedSubjectAttributeValue) {
		this.selectedSubjectAttributeValue = selectedSubjectAttributeValue;
		log.debug("Set  selectedSubjectAttributeValue: "
				+ selectedSubjectAttributeValue);
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
	 * Sets the {@code daoSubjectAttribute} property to
	 * {@code SubjectAttributeDAO} argument.
	 * 
	 * @param daoSubjectAttribute
	 */
	public void setDaoSubjectAttribute(SubjectAttributeDAO daoSubjectAttribute) {
		this.daoSubjectAttribute = daoSubjectAttribute;
		log.debug("Set  daoSubjectAttribute: " + daoSubjectAttribute);
	}

	/**
	 * Sets the {@code daoSubjectAttributeValue} property to
	 * {@code SubAttrValuesDAO} argument.
	 * 
	 * @param daoSubjectAttributeValue
	 */
	public void setDaoSubjectAttributeValue(
			SubAttrValuesDAO daoSubjectAttributeValue) {
		this.daoSubjectAttributeValue = daoSubjectAttributeValue;
		log.debug("Set  daoSubjectAttributeValue: " + daoSubjectAttributeValue);
	}

	/**
	 * Sets the {@code selectedSubject} property to {@code Subject} argument.
	 * 
	 * @param selectedSubject
	 */

	public void setSelectedSubject(Subject selectedSubject) {
		this.setAttrbtn(false);
		this.subjectAttributeValueList = new ArrayList<SubAttrValues>();
		this.selectedSubjectAttributes = null;
		this.selectedSubject = selectedSubject;

		log.debug("Set  selectedSubject: " + selectedSubject);
	}

	/**
	 * Sets the {@code SubjectAttributeValueList} property to
	 * {@code SubAttrValues} argument.
	 * 
	 * @param SubjectAttributeValueList
	 */
	public void setSubjectAttributeValueList(
			ArrayList<SubAttrValues> subjectAttributeValueList) {
		this.subjectAttributeValueList = subjectAttributeValueList;
		log.debug("Set  subjectAttributeValueList: "
				+ subjectAttributeValueList);
	}

	/**
	 * Sets the {@code SubjectList} property to {@code Subject} argument.
	 * 
	 * @param subjectList
	 */

	public void setSubjectList(ArrayList<Subject> subjectList) {
		this.subjectList = subjectList;
		log.debug("Set  subjectList: " + subjectList);
	}

	/**
	 * Sets the {@code SubjectAttributeList} property to
	 * {@code SubjectAttribute} argument.
	 * 
	 * @param SubjectAttributeList
	 */
	public void setSubjectAttributeList(
			ArrayList<SubjectAttribute> subjectAttributeList) {
		this.subjectAttributeList = subjectAttributeList;
		log.debug("Set  subjectAttributeList: " + subjectAttributeList);
	}

	/**
	 * Sets the {@code selectedSubjectAttributes} property to
	 * {@code SubjectAttribute} argument.
	 * 
	 * @param selectedSubjectAttributes
	 */
	public void setSelectedSubjectAttributes(
			SubjectAttribute selectedSubjectAttributes) {
		this.setAttrValuebtn(false);
		this.selectedSubjectAttributes = selectedSubjectAttributes;
		log.debug("Set  selectedSubjectAttributes: "
				+ selectedSubjectAttributes);
	}

	/*--------------------------------------------------------------------------*/

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
	 * Returns {@code FALSE} if an instance of the {@code Subject} is selected
	 * by the user otherwise {@code TRUE}.
	 * 
	 * @return attrbtn
	 */
	public boolean isAttrbtn() {
		log.debug("Get  attrbtn: " + attrbtn);
		return attrbtn;
	}

	/**
	 * Returns {@code FALSE} if an instance of {@code SubjectAttribute} is
	 * selected by the user otherwise {@code TRUE}.
	 * 
	 * @return attrValuebtn
	 */
	public boolean isAttrValuebtn() {
		log.debug("Get  attrValuebtn: " + attrValuebtn);
		return attrValuebtn;
	}

	/**
	 * Returns the value of {@code SubjectAttributeValueList} property
	 * 
	 * @return SubjectAttributeValueList
	 */
	public ArrayList<SubAttrValues> getSubjectAttributeValueList() {

		if (this.selectedSubjectAttributes != null) {
			log.debug("Getting  subjectAttributeValueList ");
			return (ArrayList<SubAttrValues>) new SubAttrValuesDAO()
					.populateSubValueList(selectedSubjectAttributes
							.getPkSubAttr());
		}
		log.debug("Get  subjectAttributeValueList: "
				+ subjectAttributeValueList);
		return this.subjectAttributeValueList;

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
	 * Returns the {@code List} of available Subject categories
	 * 
	 * @return
	 */
	public List<String> getCategoryList() {
		log.debug("Get  categoryList: " + categoryList);
		return categoryList;
	}

	/**
	 * Returns the value of {@code selectedSubjectAttributeValue} property
	 * 
	 * @return selectedSubjectAttributeValue
	 */
	public SubAttrValues getSelectedSubjectAttributeValue() {
		log.debug("Get  selectedSubjectAttributeValue: "
				+ selectedSubjectAttributeValue);
		return selectedSubjectAttributeValue;
	}

	/**
	 * Returns the value of {@code daoSubject} property
	 * 
	 * @return daoSubject
	 */
	public SubjectDAO getDaoSubject() {
		log.debug("Get  daoSubject: " + daoSubject);
		return daoSubject;
	}

	/**
	 * Returns the value of {@code daoSubjectAttribute } property
	 * 
	 * @return daoSubjectAttribute
	 */
	public SubjectAttributeDAO getDaoSubjectAttribute() {
		log.debug("Get  daoSubjectAttribute: " + daoSubjectAttribute);
		return daoSubjectAttribute;
	}

	/**
	 * Returns the value of {@code daoSubjectAttributeValue} property
	 * 
	 * @return daoSubjectAttributeValue
	 */
	public SubAttrValuesDAO getDaoSubjectAttributeValue() {
		log.debug("Get  daoSubjectAttributeValue: " + daoSubjectAttributeValue);
		return daoSubjectAttributeValue;
	}

	/**
	 * Returns the value of {@code selectedSubject} property
	 * 
	 * @return selectedSubject
	 */
	public Subject getSelectedSubject() {
		log.debug("Get  selectedSubject: " + selectedSubject);

		return selectedSubject;

	}

	/**
	 * Returns the {@code ArrayList} of {@code Subject} instances available.
	 * 
	 * @return SubjectList
	 */
	public ArrayList<Subject> getSubjectList() {
		log.debug("Getting  SubjectList ");
		return (ArrayList<Subject>) daoSubject.selectSubject();
	}

	/**
	 * Returns the value of {@code SubjectAttributeList } property corresponding
	 * to the {@code selectedSubject}
	 * 
	 * @return SubjectAttributeList
	 */
	public ArrayList<SubjectAttribute> getSubjectAttributeList() {
		if (this.selectedSubject != null) {
			log.debug("Getting  subjectAttributeList ");
			return (ArrayList<SubjectAttribute>) daoSubjectAttribute
					.selectSubjectAttributes(selectedSubject.getPkSubject());
		}
		log.debug("Get  subjectAttributeList: " + subjectAttributeList);
		return this.subjectAttributeList;

	}

	/**
	 * Returns the value of {@code selectedSubjectAttributes} property
	 * 
	 * @return selectedSubjectAttributes
	 */
	public SubjectAttribute getSelectedSubjectAttributes() {
		log.debug("Get  selectedSubjectAttributes: "
				+ selectedSubjectAttributes);
		return selectedSubjectAttributes;
	}

	/*--------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------*/
	/**
	 * Opens the
	 * {@code /System Learning/Subject/Add/AddSubjectAttributeValueDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of adding a new {@code SubAttrValues} instance
	 * corresponding to an @{code SubjectAttribute} of an {@code Subject}
	 * instance.
	 */
	public void addSubjectAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 150);
		options.put("width", 580);
		options.put("contentHeight", 130);
		options.put("contentWidth", 565);
		options.put("modal", true);
		log.info("Opening /System Learning/Subject/Add/AddSubjectAttributeValueDialog in a dialog.");

		context.openDialog(
				"/System Learning/Subject/Add/AddSubjectAttributeValueDialog",
				options, null);
		this.newAttributeValue = null;

	}

	/**
	 * Opens the
	 * {@code /System Learning/Subject/Add/AddSubjectAttributeDialog.xhtml} file
	 * in a Primefaces {@code  Dialog} component which offers the functionality
	 * of adding a new instance of @{code SubjectAttribute} corresponding to an
	 * existing {@code Subject} instance.
	 */
	public void addSubjectAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 250);
		options.put("width", 580);
		options.put("contentHeight", 230);
		options.put("contentWidth", 565);
		options.put("modal", true);
		log.info("Opening /System Learning/Subject/Add/AddSubjectAttributeDialog in a dialog.");

		context.openDialog(
				"/System Learning/Subject/Add/AddSubjectAttributeDialog",
				options, null);
		this.newAttributeName = null;

	}

	/**
	 * Opens the {@code /System Learning/Subject/Add/AddSubject.xhtml} page for
	 * creating a new {@code Subject} instance.
	 * 
	 * @return
	 */
	public void addSubject() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 550);
		options.put("width", 1000);
		options.put("contentHeight", 540);
		options.put("contentWidth", 960);
		options.put("modal", true);
		log.info("Opening /System Learning/Subject/Add/AddSubject in a dialog.");

		context.openDialog("/System Learning/Subject/Add/AddSubject", options,
				null);
	}

	/*--------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------*/
	/**
	 * Deletes an instance of {@code SubjectAttribute} stored in
	 * {@code selectedSubjectAttributes} property
	 */
	public void deleteSubjectAttribute() {

		this.daoSubjectAttribute
				.deleteSubjectAttribute(this.selectedSubjectAttributes
						.getPkSubAttr());
		log.info("Deleted Successfully.");
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));
		this.attrValuebtn = true;

	}

	/**
	 * Deletes the instance of {@code SubAttrValues} stored in
	 * {@code selectedSubjectAttributeValue} property
	 */
	public void deleteSubjectAttributeValue() {

		this.daoSubjectAttributeValue
				.deleteSubjectAttributeValue(this.selectedSubjectAttributeValue
						.getPkSubAttrVal());
		log.info("Deleted Successfully.");
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Deleted Successfully"));
	}

	/**
	 * Deletes the instance of {@code Subject} stored in {@code selectedSubject}
	 * property
	 */
	public void deleteSubject() {
		this.daoSubject.deleteSubject(this.selectedSubject.getPkSubject());
		log.info("Subject Deleted Successfully.");
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage(" Successful Execution",
						"Subject Deleted Successfully"));
		this.attrbtn = true;
		this.attrValuebtn = true;

	}

	/*--------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------*/
	/**
	 * Opens the
	 * {@code /System Learning/Subject/Update/UpdateSubjectDialog.xhtml} file in
	 * a Primefaces {@code  Dialog} component which offers the functionality of
	 * updating the name and description of an existing {@code Subject}
	 * instance.
	 */
	public void updateSubject() {

		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("scrollable", true);
		options.put("dynamic", true);
		options.put("height", 300);
		options.put("width", 600);
		options.put("contentHeight", 280);
		options.put("contentWidth", 580);
		options.put("modal", true);
		log.info("Opening /System Learning/Subject/Update/UpdateSubjectDialog in a dialog.");

		context.openDialog(
				"/System Learning/Subject/Update/UpdateSubjectDialog", options,
				null);
	}

	/**
	 * Opens the
	 * {@code /System Learning/Subject/Update/UpdateSubjectAttributeDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating the existing {@code SubjectAttribute} of an
	 * {@code Subject} instance.
	 */
	public void updateSubjectAttribute() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 115);
		options.put("width", 565);
		options.put("contentHeight", 100);
		options.put("contentWidth", 550);
		options.put("modal", true);
		log.info("Opening /System Learning/Subject/Update/UpdateSubjectAttributeDialog in a dialog.");

		context.openDialog(
				"/System Learning/Subject/Update/UpdateSubjectAttributeDialog",
				options, null);

	}

	/**
	 * Opens the
	 * {@code /System Learning/Subject/Update/UpdateSubjectAttributeValueDialog.xhtml}
	 * file in a Primefaces {@code  Dialog} component which offers the
	 * functionality of updating the value of an existing @
	 * {@code SubAttrValues} corresponding to an @{code SubjectAttribute} of an
	 * {@code Subject} instance.
	 */
	public void updateSubjectAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("resizable", false);
		options.put("dynamic", true);
		options.put("height", 115);
		options.put("width", 565);
		options.put("contentHeight", 100);
		options.put("contentWidth", 550);
		options.put("modal", true);
		log.info("Opening  /System Learning/Subject/Update/UpdateSubjectAttributeValueDialog in a dialog.");

		context.openDialog(
				"/System Learning/Subject/Update/UpdateSubjectAttributeValueDialog",
				options, null);

	}

	/*--------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------*/

	/**
	 * Saves the updated value of {@code selectedSubjectAttributeValue} property
	 * in the database.
	 */
	public void saveUpdateSubjectAttributeValue() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.selectedSubjectAttributeValue.getSubAttrValue() == null) {
			log.info("Opening /Misc/ValueWarning in a dialog.");

			context.openDialog("/Misc/ValueWarning");

			return;

		} else {
			this.daoSubjectAttributeValue.updateSubAttrValue(
					this.selectedSubjectAttributeValue.getPkSubAttrVal(),
					this.selectedSubjectAttributeValue.getSubAttrValue());
			log.info("Closing dialog.");
			context.closeDialog(this);

			this.operationFail = false;
			return;
		}

	}

	/**
	 * Saves the updated value of {@code selectedSubjectAttributes} property in
	 * the database.
	 */
	public void saveUpdateSubjectAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.selectedSubjectAttributes.getSubjAttrId() == null) {
			log.info("Opening  /Misc/NameWarning in a dialog.");
			context.openDialog("/Misc/NameWarning");

			return;

		} else {
			this.daoSubjectAttribute.updateSubjectAttr(
					this.selectedSubjectAttributes.getPkSubAttr(),
					this.selectedSubjectAttributes.getSubjAttrId());
			log.info("Closing dialog.");
			context.closeDialog(this);

			this.operationFail = false;
			return;
		}

	}

	/**
	 * Saves the updated value of {@code selectedSubject} property in the
	 * database.
	 */
	public void saveUpdateSubject() {
		RequestContext context = RequestContext.getCurrentInstance();
		if (this.selectedSubject.getSubjectName() == null) {
			log.info("Opening /Misc/NameWarning in a dialog.");
			context.openDialog("/Misc/NameWarning");
			return;

		} else {

			this.daoSubject.updateSubject(this.selectedSubject.getPkSubject(),
					this.selectedSubject.getDescription(),
					this.selectedSubject.getSubjectName(),
					this.selectedSubject.getSubjectCategory());
			log.info("Closing dialog.");
			context.closeDialog(this);

			this.operationFail = false;
			return;
		}

	}

	/**
	 * Saves the newly added instance of {@code SubjectAttribute}in the database
	 * corresponding to an existing {@code Subject} instance referred by
	 * {@code selectedSubject}
	 */
	public void saveAddSubjectAttribute() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.newAttributeName == null) {
			log.info("Opening /Misc/NameWarning in a dialog.");

			context.openDialog("/Misc/NameWarning");

			return;

		} else {
			this.daoSubjectAttribute.createSubjectAttrValue(
					this.selectedSubject, this.newAttributeName,
					this.selectedDataType, this.newAttributeValue);
			log.info("Closing dialog.");

			context.closeDialog(this);

			this.newAttributeName = null;
			this.newAttributeValue = null;
			this.selectedDataType = null;
			this.operationFail = false;
			return;
		}

	}

	/**
	 * Saves the newly added instance of {@code SubAttrValues}in the database
	 * corresponding to an existing {@code SubjectAttribute} instance referred
	 * by {@code selectedSubjectAttributes}
	 */
	public void saveAddSubjectAttributeValue() {

		RequestContext context = RequestContext.getCurrentInstance();

		if (this.newAttributeValue == null) {
			log.info("Opening /Misc/ValueWarning in a dialog.");
			context.openDialog("/Misc/ValueWarning");

			return;

		} else {
			this.daoSubjectAttributeValue.createSubAttrValue(
					this.selectedSubjectAttributes, this.newAttributeValue);
			log.info("Closing dialog.");
			context.closeDialog(this);
			log.info("Subject Attribute Value Added Successfully.");
			context.showMessageInDialog(new FacesMessage(
					FacesMessage.SEVERITY_INFO, "Successful Execution",
					"Subject Attribute Value Added Successfully."));

			this.newAttributeValue = null;

			this.operationFail = false;
			return;
		}

	}

	/*--------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------*/

	/**
	 * Cancels the operation of updating an existing {@code SubAttrValues}
	 * instance.
	 */

	public void cancelUpdateSubjectAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);

	}

	/**
	 * Cancels the operation of updating an existing {@code SubAttrValues}
	 * instance.
	 */
	public void cancelUpdateSubjectAttribute() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);

	}

	/**
	 * Cancels the operation of updating an existing {@code Subject} instance.
	 */
	public void cancelUpdateSubject() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");

		context.closeDialog(this);

	}

	/**
	 * Cancels the operation of adding a new {@code SubAttrValues} corresponding
	 * to an existing {@code SubjectAttribute} instance
	 */
	public void cancelAddSubjectAttributeValue() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);
		this.newAttributeValue = null;

	}

	/**
	 * Cancels the operation of adding an existing {@code SubjectAttribute}
	 * instance corresponding to an existing {@code Subject} instance.
	 */
	public void cancelAddSubjectAttribute() {
		RequestContext context = RequestContext.getCurrentInstance();
		log.info("Closing dialog.");
		context.closeDialog(this);
		this.newAttributeName = null;
		this.selectedDataType = null;

	}

	/*--------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------*/
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

	public void showHelpMessage() {
		FacesContext.getCurrentInstance().addMessage(
				null,
				new FacesMessage("Subject Help Dialog",
						"This is the subject dialog"));

		RequestContext.getCurrentInstance().showMessageInDialog(
				new FacesMessage(FacesMessage.SEVERITY_INFO,
						"What we do in life", "Echoes in eternity."));

	}

	/*--------------------------------------------------------------------------*/
	/*--------------------------------------------------------------------------*/
	/**
	 * Disables the buttons for adding {@code SubjectAttribute} and
	 * {@code SubAttrValues} instances corresponding to an existing
	 * {@code Subject} instance.
	 */
	public void onSubjectUnSelect() {
		this.attrbtn = true;
		this.attrValuebtn = true;
	}

	/**
	 * Disables the button for adding {@code SubAttrValues} instance
	 * corresponding to an existing {@code SubjectAttribute} instance.
	 */
	public void onSubjectAttributeUnSelect() {
		this.attrValuebtn = true;
	}

	/**
	 * Disables the button for adding {@code SubAttrValues} instance and enables
	 * the button for adding {@code SubjectAttribute} instance whenever a
	 * {@code Subject} instance is selected.
	 */
	public void onSubjectSelect() {
		this.attrbtn = false;
		this.attrValuebtn = true;
	}

}
