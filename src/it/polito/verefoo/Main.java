package it.polito.verefoo;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.util.List;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import it.polito.verefoo.extra.Package1LoggingClass;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.xml.sax.SAXException;

import it.polito.verefoo.extra.BadGraphError;
import it.polito.verefoo.jaxb.*;
import it.polito.verefoo.utils.TestResults;
/**
 * This is the main class only for testing the Verefoo execution
 *
 */

public class Main {
	static Logger loggerInfo = LogManager.getLogger(Main.class);
	static Logger loggerResult = LogManager.getLogger("result");
	
	static ch.qos.logback.classic.Logger loggerTest = Package1LoggingClass.createLoggerFor("results", "log/results");
	
	public static void main(String[] args) throws MalformedURLException {
		System.setProperty("log4j.configuration", new File("resources", "log4j2.xml").toURI().toURL().toString());
		try {
			JAXBContext jc;
			jc = JAXBContext.newInstance("it.polito.verefoo.jaxb");
			Unmarshaller u = jc.createUnmarshaller();
			SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
			Schema schema = sf.newSchema(new File("./xsd/nfvSchema.xsd"));
			u.setSchema(schema);

			for(int i=0; i<10; i++) {
				long beginAll = System.currentTimeMillis();
				try {
					Marshaller m = jc.createMarshaller();
					m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
					m.setProperty(Marshaller.JAXB_NO_NAMESPACE_SCHEMA_LOCATION, "./xsd/nfvSchema.xsd");
					VerefooSerializer test = new VerefooSerializer((NFV) u.unmarshal(new FileInputStream("./testfile/firewall-analysis/AlShaer10Random.xml")));
					

					for(TestResults tr: test.getTestResults().values()) {
						tr.print();
					}
					
				} catch (BadGraphError | FileNotFoundException e) {
					loggerInfo.error("Graph semantically incorrect");
					loggerInfo.error(e);
					System.exit(1);
				}
				long endAll = System.currentTimeMillis();
				//loggerResult.info("time: " + (endAll - beginAll) + "ms;");
				loggerTest.info("time: " + (endAll - beginAll) + "ms;");
				
			}
			
		} catch (JAXBException je) {
			loggerInfo.error("Error while unmarshalling or marshalling");
			loggerInfo.error(je);
			System.exit(1);
		} catch (ClassCastException cce) {
			loggerInfo.error("Wrong data type found in XML document");
			loggerInfo.error(cce);
			System.exit(1);
		} catch (BadGraphError e) {
			loggerInfo.error("Graph semantically incorrect");
			loggerInfo.error(e);
			System.exit(1);
		} catch (SAXException e) {
			loggerInfo.error(e);
			System.exit(1);
		}
	}

}
