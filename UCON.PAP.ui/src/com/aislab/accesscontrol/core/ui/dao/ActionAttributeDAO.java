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

import com.aislab.accesscontrol.core.entities.ActAttrValues;
import com.aislab.accesscontrol.core.entities.Action;
import com.aislab.accesscontrol.core.entities.ActionAttribute;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

/**
 * Class for querying Database for queries related to Action Attributes
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Ummair Asghar <10beseuasghar@seecs.edu.pk>
 * @version 1.0
 * 
 */

public class ActionAttributeDAO {
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
	 * Fetching list of action attributes based on action selection
	 * 
	 * @param actPk
	 *            primary key of action
	 * 
	 * 
	 * @return List<ActionAttribute> List of action attributes
	 * 
	 */

	@SuppressWarnings("unchecked")
	public List<ActionAttribute> selectActionAttributes(Long actPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("select act.actionAttributes from Action act where act.pkAction ="
						+ actPk);
		List<ActionAttribute> actAttr = query.list();

		tx.commit();
		session.close();
		return actAttr;

	}

	/**
	 * Selecting action attribute
	 * 
	 * @param actAttrPk
	 *            primary key of action attribute
	 * 
	 * 
	 * @return ActionAttribute Value of action attribute
	 * 
	 */

	public ActionAttribute selectActionAttribute(Long actAttrPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from ActionAttribute actAttr where actAttr.pkActAttr = "
						+ actAttrPk);
		ActionAttribute actAttr = (ActionAttribute) query.uniqueResult();

		tx.commit();
		session.close();
		return actAttr;

	}

	/**
	 * Populating list of action attributes based on action selection
	 * 
	 * @param actPk
	 *            primary key of action
	 * 
	 * 
	 * @return List<String> List of action attributes
	 * 
	 */

	@SuppressWarnings("unchecked")
	public List<String> populateActAttrList(Long actPk) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("select actAttrId from ActionAttribute actAttr"
						+ " where actAttr.action = " + actPk);
		List<String> actAttr = query.list();

		tx.commit();
		session.close();
		return actAttr;

	}

	/**
	 * Creating a new action attribute
	 * 
	 * @param action
	 *            value of action
	 * 
	 * 
	 * @param actAttrId
	 *            Action attribute id
	 * 
	 * 
	 */

	public void createActionAttr(Action action, String actAttrId) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		ActionAttribute actAttr = new ActionAttribute(action, actAttrId);

		session.persist(actAttr);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new action attribute value
	 * 
	 * @param action
	 *            value of action
	 * 
	 * 
	 * @param actAttrId
	 *            Action attribute id
	 * 
	 * 
	 * @param attrValue
	 *            value of action attribute
	 * 
	 */

	public void createActionAttrValue(Action action, String actAttrId,
			String attrValue) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		ActionAttribute actAttr = new ActionAttribute(action, actAttrId);
		ActAttrValues attrVal = new ActAttrValues(actAttr, attrValue);

		session.persist(actAttr);
		session.persist(attrVal);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new action attribute value
	 * 
	 * @param action
	 *            value of action
	 * 
	 * 
	 * @param actAttrId
	 *            Action attribute id
	 * 
	 * 
	 * @param dataType
	 *            dataType of action
	 * 
	 * 
	 * @param attrValue
	 *            value of action attribute
	 * 
	 */

	public void createActionAttrValue(Action action, String actAttrId,
			String dataType, String attrValue) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		ActionAttribute actAttr = new ActionAttribute(action, actAttrId,
				dataType);
		ActAttrValues attrVal = new ActAttrValues(actAttr, attrValue);

		session.persist(actAttr);
		session.persist(attrVal);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new action attribute
	 * 
	 * @param action
	 *            value of action
	 * 
	 * 
	 * @param actAttrId
	 *            Action attribute id
	 * 
	 * 
	 * @param dataType
	 *            dataType of action
	 * 
	 */

	public void createActionAttr(Action action, String actAttrId,
			String dataType) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		ActionAttribute actAttr = new ActionAttribute(action, actAttrId,
				dataType);

		session.persist(actAttr);
		tx.commit();
		session.close();
	}

	/**
	 * Updating an action attribute
	 * 
	 * @param actAttrPk
	 *            primary key of action
	 * 
	 * 
	 * @param actAttrId
	 *            Action attribute id
	 * 
	 * 
	 */

	public void updateActionAttr(Long actAttrPk, String actAttrId) {
		selectActionAttributes(actAttrPk);
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		ActionAttribute actAttr = (ActionAttribute) session.load(
				ActionAttribute.class, actAttrPk);
		actAttr.setActAttrId(actAttrId);

		session.persist(actAttr);
		tx.commit();
		session.close();
	}

	/**
	 * Deleting an action attribute
	 * 
	 * @param pkActAttr
	 *            primary key of action
	 * 
	 * 
	 */

	public void deleteActionAttribute(Long pkActAttr) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session
				.createQuery("from ActionAttribute a where a.pkActAttr = "
						+ pkActAttr);
		ActionAttribute actAttr = (ActionAttribute) query.uniqueResult();

		session.delete(actAttr);
		tx.commit();
		session.close();
	}

}
