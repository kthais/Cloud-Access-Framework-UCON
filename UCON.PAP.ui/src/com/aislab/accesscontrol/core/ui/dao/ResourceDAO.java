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


import com.aislab.accesscontrol.core.entities.ResAttrValues;
import com.aislab.accesscontrol.core.entities.Resource;
import com.aislab.accesscontrol.core.entities.ResourceAttribute;
import com.aislab.accesscontrol.core.ui.util.HibernateUtil;

/**
 * Class for querying Database for queries related to Resource Elements
 * 
 * @author Yumna Ghazi <09bicseyghazi@seecs.edu.pk>
 * @author Ummair Asghar <10beseuasghar@seecs.edu.pk>
 * @version 1.0
 * 
 */

public class ResourceDAO {
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
	 * Fetching list of resource elements from database
	 * 
	 * @return list of resource elements
	 */

	@SuppressWarnings("unchecked")
	public List<Resource> selectResource() {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();
		query = session.createQuery("from Resource");
		List<Resource> res = query.list();

		tx.commit();
		session.close();
		return res;
	}

	/**
	 * Creating a new resource
	 * 
	 * @param res
	 *            value of the resource
	 * 
	 * 
	 */
	public void createResource(Resource res) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		session.persist(res);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new resource
	 * 
	 * @param description
	 *            description of the resource
	 * 
	 * @param resource
	 *            value of the resource
	 * 
	 */

	public void createResource(String description, String resource) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Resource res = new Resource(resource, description);
		session.persist(res);
		tx.commit();
		session.close();
	}

	/**
	 * Creating a new resource
	 * 
	 * @param description
	 *            description of the resource
	 * 
	 * @param resource
	 *            value of the resource
	 * 
	 * @param resAttr
	 *            list of resource attributes
	 * 
	 */

	public void createResource(String description, String resource,
			List<ResourceAttribute> resAttr) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		Resource res = new Resource(resource, description);

		res.setResourceAttributes(new HashSet<ResourceAttribute>(resAttr));
		session.persist(res);

		for (ResourceAttribute attr : resAttr) {
			attr.setResource(res);
			session.persist(attr);

			for (ResAttrValues val : attr.getResAttrValues()) {
				val.setResourceAttribute(attr);
				session.persist(val);
			}

		}
		tx.commit();
		session.close();
	}

	/**
	 * Updating a resource
	 * 
	 * 
	 * @param pkResource
	 *            primary key of the resource
	 * 
	 * @param description
	 *            description of the resource
	 * 
	 * @param resource
	 *            value of the resource
	 * 
	 * @param resAttr
	 *            list of resource attributes
	 * 
	 */

	public void updateResource(Long pkResource, String description,
			String resource, List<ResourceAttribute> resAttr) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Resource s where s.pkResource ="
				+ pkResource);
		Resource res = (Resource) query.uniqueResult();
		res.setDescription(description);
		res.setResourceName(resource);
		res.setResourceAttributes(new HashSet<ResourceAttribute>(resAttr));
		session.persist(res);
		tx.commit();
		session.close();
	}

	/**
	 * Updating a resource
	 * 
	 * 
	 * @param pkResource
	 *            primary key of the resource
	 * 
	 * @param description
	 *            description of the resource
	 * 
	 * @param resource
	 *            value of the resource
	 * 
	 * 
	 */

	public void updateResource(Long pkResource, String description,
			String resource) {
		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Resource r where r.pkResource ="
				+ pkResource);
		Resource res = (Resource) query.uniqueResult();
		res.setDescription(description);
		res.setResourceName(resource);

		session.persist(res);
		tx.commit();
		session.close();
	}

	/**
	 * Deleting a resource
	 * 
	 * 
	 * @param pkResource
	 *            primary key of the resource
	 * 
	 * 
	 */

	
	public void deleteResource(Long pkResource) {

		sessionFactory = HibernateUtil.configureSessionFactory();
		session = sessionFactory.openSession();
		tx = session.beginTransaction();

		query = session.createQuery("from Resource r where r.pkResource = "
				+ pkResource);
		Resource res = (Resource) query.uniqueResult();

		session.delete(res);
		tx.commit();
		session.close();
	}

}
