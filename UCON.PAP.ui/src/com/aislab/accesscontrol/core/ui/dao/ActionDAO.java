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

import java.util.HashSet;
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
 * Class for querying Database for queries related to Action Elements
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Ummair Asghar <10beseuasghar@seecs.edu.pk>
 * @version 1.0
 * 
 */

public class ActionDAO {
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
	 * Fetching list of action elements from database
	 * 
	 * @return list of action elements
	 */

	@SuppressWarnings("unchecked")
	public List<Action> selectAction() {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from Action");
		List<Action> act = query.list();

		tx.commit();
		session.close();
		return act;
	}

	/**
	 * Creating a new action
	 * 
	 * @param act
	 *            value of the action
	 * 
	 * 
	 */
	public void createAction(Action act) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		session.persist(act);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new action
	 * 
	 * @param description
	 *            description of the action
	 * 
	 * @param action
	 *            value of the action
	 * 
	 */

	public void createAction(String description, String action) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Action act = new Action(action, description);
		session.persist(act);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new action
	 * 
	 * @param description
	 *            description of the action
	 * 
	 * @param action
	 *            value of the action
	 * 
	 * @param actAttr
	 *            list of action attributes
	 * 
	 */

	public void createAction(String description, String action,
			List<ActionAttribute> actAttr) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Action act = new Action(action, description);

		act.setActionAttributes(new HashSet<ActionAttribute>(actAttr));
		session.persist(act);

		for (ActionAttribute attr : actAttr) {
			attr.setAction(act);
			session.persist(attr);

			for (ActAttrValues val : attr.getActAttrValues()) {
				val.setActionAttribute(attr);
				session.persist(val);
			}

		}
		tx.commit();
		session.close();
	}

	/**
	 * Updating an action
	 * 
	 * 
	 * @param pkAction
	 *            primary key of the action
	 * 
	 * @param description
	 *            description of the action
	 * 
	 * @param action
	 *            value of the action
	 * 
	 * @param actAttr
	 *            list of action attributes
	 * 
	 */

	public void updateAction(Long pkAction, String description, String action,
			List<ActionAttribute> actAttr) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Action a where a.pkAction ="
				+ pkAction);
		Action act = (Action) query.uniqueResult();
		act.setDescription(description);
		act.setActionName(action);
		act.setActionAttributes(new HashSet<ActionAttribute>(actAttr));
		session.persist(act);
		tx.commit();
		session.close();
	}

	/**
	 * Updating an action
	 * 
	 * 
	 * @param pkAction
	 *            primary key of the action
	 * 
	 * @param description
	 *            description of the action
	 * 
	 * @param action
	 *            value of the action
	 * 
	 * 
	 */

	public void updateAction(Long pkAction, String description, String action) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Action a where a.pkAction ="
				+ pkAction);
		Action act = (Action) query.uniqueResult();
		act.setDescription(description);
		act.setActionName(action);

		session.persist(act);
		tx.commit();
		session.close();
	}

	/**
	 * Deleting an action
	 * 
	 * 
	 * @param pkAction
	 *            primary key of the action
	 * 
	 * 
	 */


	public void deleteAction(Long pkAction) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Action r where r.pkAction = "
				+ pkAction);
		Action act = (Action) query.uniqueResult();

		session.delete(act);
		tx.commit();
		session.close();
	}
}
