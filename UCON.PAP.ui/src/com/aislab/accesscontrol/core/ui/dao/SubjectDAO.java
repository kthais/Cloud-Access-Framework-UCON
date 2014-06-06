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


import com.aislab.accesscontrol.core.entities.SubAttrValues;
import com.aislab.accesscontrol.core.entities.Subject;
import com.aislab.accesscontrol.core.entities.SubjectAttribute;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

/**
 * Class for querying Database for queries related to Subject Elements
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Ummair Asghar <10beseuasghar@seecs.edu.pk>
 * @version 1.0
 * 
 */

public class SubjectDAO {
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
	 * Fetching list of subject elements from database
	 * 
	 * @return list of subject elements
	 */

	@SuppressWarnings("unchecked")
	public List<Subject> selectSubject() {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from Subject");
		List<Subject> subs = query.list();

		tx.commit();
		session.close();
		return subs;
	}

	/**
	 * Creating a new subject
	 * 
	 * @param sub
	 *            value of the subject
	 * 
	 * 
	 */
	public void createSubject(Subject sub) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		session.persist(sub);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new subject
	 * 
	 * @param description
	 *            description of the subject
	 * 
	 * @param subject
	 *            value of the subject
	 * 
	 * @param subjectCategory
	 *            category of subject
	 * 
	 */

	public void createSubject(String description, String subject,
			String subjectCategory) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Subject sub = new Subject(subject, description, subjectCategory);
		session.persist(sub);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new subject
	 * 
	 * @param description
	 *            description of the subject
	 * 
	 * @param subject
	 *            value of the subject
	 * 
	 * @param subjectCategory
	 *            category of subject
	 * 
	 * @param subAttr
	 *            list of subject attributes
	 * 
	 */

	public void createSubject(String description, String subject,
			String subjectCategory, List<SubjectAttribute> subAttr) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Subject sub = new Subject(subject, description, subjectCategory);

		sub.setSubjectAttributes(new HashSet<SubjectAttribute>(subAttr));
		session.persist(sub);

		for (SubjectAttribute attr : subAttr) {
			attr.setSubject(sub);
			session.persist(attr);

			for (SubAttrValues val : attr.getSubAttrValues()) {
				val.setSubjectAttribute(attr);
				session.persist(val);
			}

		}

		tx.commit();
		session.close();
	}

	/**
	 * Updating a subject
	 * 
	 * 
	 * @param pkSubject
	 *            primary key of the subject
	 * 
	 * @param description
	 *            description of the subject
	 * 
	 * @param subject
	 *            value of the subject
	 * 
	 * @param subAttr
	 *            list of subject attributes
	 * 
	 */

	public void updateSubject(Long pkSubject, String description,
			String subject, String subjectCategory,
			List<SubjectAttribute> subAttr) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Subject s where s.pkSubject ="
				+ pkSubject);
		Subject sub = (Subject) query.uniqueResult();
		sub.setDescription(description);
		sub.setSubjectName(subject);
		sub.setSubjectCategory(subjectCategory);
		sub.setSubjectAttributes(new HashSet<SubjectAttribute>(subAttr));
		session.persist(sub);
		tx.commit();
		session.close();
	}

	/**
	 * Updating a subject
	 * 
	 * 
	 * @param pkSubject
	 *            primary key of the subject
	 * 
	 * @param description
	 *            description of the subject
	 * 
	 * @param subject
	 *            value of the subject
	 * 
	 * @param subjectCategory
	 *            category of subject
	 * 
	 */

	public void updateSubject(Long pkSubject, String description,
			String subject, String subjectCategory) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Subject s where s.pkSubject ="
				+ pkSubject);
		Subject sub = (Subject) query.uniqueResult();
		sub.setDescription(description);
		sub.setSubjectName(subject);
		sub.setSubjectCategory(subjectCategory);

		session.persist(sub);
		tx.commit();
		session.close();
	}

	/**
	 * Deleting a subject
	 * 
	 * 
	 * @param pkSubject
	 *            primary key of the subject
	 * 
	 * 
	 */

	
	public void deleteSubject(Long pkSubject) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Subject s where s.pkSubject = "
				+ pkSubject);
		Subject sub = (Subject) query.uniqueResult();

		session.delete(sub);
		tx.commit();
		session.close();
	}
}
