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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.hibernate.Query;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;

import com.aislab.accesscontrol.core.entities.Action;
import com.aislab.accesscontrol.core.entities.Apply;
import com.aislab.accesscontrol.core.entities.Condition;
import com.aislab.accesscontrol.core.entities.Environment;
import com.aislab.accesscontrol.core.entities.Expression;
import com.aislab.accesscontrol.core.entities.Resource;
import com.aislab.accesscontrol.core.entities.Subject;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

/**
 * Class for querying Database for queries related to Condition Elements
 * 
 * @author Salman Ahmad Ansari <10besesansari@seecs.edu.pk>
 * @version 1.0
 * 
 */
@SuppressWarnings("serial")
public class ConditionDAO implements Serializable {

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
	 * Creating a new Condition
	 * 
	 * @param cond
	 *            value of Condition
	 */
	public void createCondition(Condition cond) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		session.persist(cond);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new Expression
	 * 
	 * @param exp
	 *            value of Expression
	 */
	public void createExpression(Expression exp) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		session.persist(exp);
		tx.commit();
		session.close();
	}

	/**
	 * Creating all new Expressions send as an argument
	 * 
	 * @param exp
	 *            value of Expressions
	 */
	public void createExpression(ArrayList<Expression> exp) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		for (Expression e : exp)
			session.persist(e);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new Apply
	 * 
	 * @param app
	 *            value of Apply
	 */
	public void createApply(Apply app) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		session.persist(app);
		tx.commit();
		session.close();
	}

	/**
	 * Creating all new Applies received as an argument
	 * 
	 * @param app
	 *            value of Applies
	 */
	public void createApply(ArrayList<Apply> app) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		for (Apply a : app)
			session.persist(a);
		tx.commit();
		session.close();
	}

	/**
	 * Fetching list of all conditions from the database
	 * 
	 * @return list of Condition Elements
	 */
	public List<Condition> selectCondition() {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Query query = session.createQuery("from Condition");
		@SuppressWarnings("unchecked")
		List<Condition> cond = query.list();

		tx.commit();
		session.close();
		return cond;
	}

	/**
	 * Deleting a Condition
	 * 
	 * @param cond
	 *            value of condition
	 */
	public void deleteCondition(Condition cond) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Expression testApply = cond.getExpression();

		session.delete(testApply);
		// session.delete(cond);

		tx.commit();
		session.close();
	}
	
	public List<Subject> getSubject(){
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Query query = session.createQuery("from Subject");
		@SuppressWarnings("unchecked")
		List<Subject> subj = query.list();

		tx.commit();
		session.close();
		return subj;
		
	}
	
	public List<Action> getAction(){
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Query query = session.createQuery("from Action");
		@SuppressWarnings("unchecked")
		List<Action> act = query.list();

		tx.commit();
		session.close();
		return act;
		
	}
	
	public List<Resource> getResource(){
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Query query = session.createQuery("from Resource");
		@SuppressWarnings("unchecked")
		List<Resource> res = query.list();

		tx.commit();
		session.close();
		return res;
		
	}
	
	public List<Environment> getEnvironment(){
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Query query = session.createQuery("from Environment");
		@SuppressWarnings("unchecked")
		List<Environment> env = query.list();

		tx.commit();
		session.close();
		return env;
		
	}

}
