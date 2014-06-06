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

package com.aislab.accesscontrol.core.ui.dao;

import java.util.List;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;

import com.aislab.accesscontrol.core.entities.SubAttrValues;
import com.aislab.accesscontrol.core.entities.Subject;
import com.aislab.accesscontrol.core.entities.SubjectAttribute;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

/**
 * Class for querying Database for queries related to Subject Attributes
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Ummair Asghar <10beseuasghar@seecs.edu.pk>
 * @version 1.0
 * 
 */

public class SubjectAttributeDAO {
	/**
	 * A SessionFactory variable to configure the database session
	 */
	public static SessionFactory sessionFactory;

	/**
	 * A Session variable to store the session opened
	 */
	public static Session session;

	/**
	 * A Transaction variable used to start a transaction in a session
	 */
	public static Transaction tx;

	/**
	 * A Query variable used to retrieve information from database
	 */
	Query query;

	/**
	 * Fetching list of subject attributes based on subject selection
	 * 
	 * @param subPk
	 *            primary key of subject
	 * 
	 * @return List<SubjectAttribute> List of subject attributes
	 * 
	 */

	@SuppressWarnings("unchecked")
	public List<SubjectAttribute> selectSubjectAttributes(Long subPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("select sub.subjectAttributes from Subject sub where sub.pkSubject ="
						+ subPk);
		List<SubjectAttribute> subAttr = query.list();

		tx.commit();
		session.close();
		return subAttr;

	}

	/**
	 * Selecting subject attribute
	 * 
	 * @param subAttrPk
	 *            primary key of subject attribute
	 * 
	 * 
	 * @return SubjectAttribute Value of subject attribute
	 * 
	 */

	public SubjectAttribute selectSubjectAttribute(Long subAttrPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from SubjectAttribute subAttr where subAttr.pkSubAttr = "
						+ subAttrPk);
		SubjectAttribute subAttr = (SubjectAttribute) query.uniqueResult();

		tx.commit();

		return subAttr;

	}

	/**
	 * Populating list of subject attributes based on subject selection
	 * 
	 * @param subPk
	 *            primary key of subject
	 * 
	 * @return List<String> List of subject attributes
	 * 
	 */

	@SuppressWarnings("unchecked")
	public List<String> populateSubAttrList(Long subPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("select subjAttrId from SubjectAttribute subAttr"
						+ " where subAttr.subject = " + subPk);
		List<String> subAttr = query.list();

		tx.commit();
		session.close();
		return subAttr;

	}

	/**
	 * Creating a new subject attribute
	 * 
	 * @param subject
	 *            value of subject
	 * 
	 * 
	 * @param subjAttrId
	 *            Subject attribute id
	 * 
	 * 
	 */

	public void createSubjectAttr(Subject subject, String subjAttrId) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		SubjectAttribute subAttr = new SubjectAttribute(subject, subjAttrId);

		session.persist(subAttr);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new subject attribute value
	 * 
	 * @param subject
	 *            value of subject
	 * 
	 * 
	 * @param subjAttrId
	 *            Subject attribute id
	 * 
	 * 
	 * @param attrValue
	 *            value of subject attribute
	 * 
	 */

	public void createSubjectAttrValue(Subject subject, String subjAttrId,
			String attrValue) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		SubjectAttribute subAttr = new SubjectAttribute(subject, subjAttrId);
		SubAttrValues attrVal = new SubAttrValues(subAttr, attrValue);

		session.persist(subAttr);
		session.persist(attrVal);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new subject attribute value
	 * 
	 * @param subject
	 *            value of subject
	 * 
	 * 
	 * @param subjAttrId
	 *            Subject attribute id
	 * 
	 * 
	 * @param dataType
	 *            dataType of subject
	 * 
	 * @param attrValue
	 *            value of subject attribute
	 * 
	 */

	public void createSubjectAttrValue(Subject subject, String subjAttrId,
			String dataTrype, String attrValue) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		SubjectAttribute subAttr = new SubjectAttribute(subject, subjAttrId,
				dataTrype);
		SubAttrValues attrVal = new SubAttrValues(subAttr, attrValue);

		session.persist(subAttr);
		session.persist(attrVal);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new subject attribute
	 * 
	 * @param subject
	 *            value of subject
	 * 
	 * 
	 * @param subjAttrId
	 *            Subject attribute id
	 * 
	 * 
	 * @param dataType
	 *            dataType of subject
	 * 
	 */

	public void createSubjectAttr(Subject subject, String subjAttrId,
			String dataType) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		SubjectAttribute subAttr = new SubjectAttribute(subject, subjAttrId,
				dataType);

		session.persist(subAttr);
		tx.commit();
		session.close();
	}

	/**
	 * Updating a subject attribute
	 * 
	 * @param subAttrPk
	 *            primary key of subject
	 * 
	 * 
	 * @param subjAttrId
	 *            Subject attribute id
	 * 
	 * 
	 */

	public void updateSubjectAttr(Long subAttrPk, String subjAttrId) {
		selectSubjectAttributes(subAttrPk);
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		SubjectAttribute subAttr = (SubjectAttribute) session.load(
				SubjectAttribute.class, subAttrPk);
		subAttr.setSubjAttrId(subjAttrId);

		session.persist(subAttr);
		tx.commit();
		session.close();
	}

	/**
	 * Deleting a subject attribute
	 * 
	 * @param pkSubAttr
	 *            primary key of subject
	 * 
	 * 
	 */

	public void deleteSubjectAttribute(Long pkSubAttr) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from SubjectAttribute s where s.pkSubAttr = "
						+ pkSubAttr);
		SubjectAttribute subAttr = (SubjectAttribute) query.uniqueResult();

		session.delete(subAttr);
		tx.commit();
		session.close();
	}

}
