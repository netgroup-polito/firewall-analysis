//
// Questo file è stato generato dall'architettura JavaTM per XML Binding (JAXB) Reference Implementation, v2.2.11 
// Vedere <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Qualsiasi modifica a questo file andrà persa durante la ricompilazione dello schema di origine. 
// Generato il: 2023.03.20 alle 04:53:12 PM CET 
//


package it.polito.verefoo.jaxb;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Classe Java per anonymous complex type.
 * 
 * <p>Il seguente frammento di schema specifica il contenuto previsto contenuto in questa classe.
 * 
 * <pre>
 * &lt;complexType&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="AllocationConstraint" maxOccurs="unbounded" minOccurs="0"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;attribute name="type" use="required" type="{}AllocationConstraintType" /&gt;
 *                 &lt;attribute name="nodeA" use="required" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *                 &lt;attribute name="nodeB" use="required" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {
    "allocationConstraint"
})
@XmlRootElement(name = "AllocationConstraints")
public class AllocationConstraints {

    @XmlElement(name = "AllocationConstraint")
    protected List<AllocationConstraints.AllocationConstraint> allocationConstraint;

    /**
     * Gets the value of the allocationConstraint property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the allocationConstraint property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getAllocationConstraint().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link AllocationConstraints.AllocationConstraint }
     * 
     * 
     */
    public List<AllocationConstraints.AllocationConstraint> getAllocationConstraint() {
        if (allocationConstraint == null) {
            allocationConstraint = new ArrayList<AllocationConstraints.AllocationConstraint>();
        }
        return this.allocationConstraint;
    }


    /**
     * <p>Classe Java per anonymous complex type.
     * 
     * <p>Il seguente frammento di schema specifica il contenuto previsto contenuto in questa classe.
     * 
     * <pre>
     * &lt;complexType&gt;
     *   &lt;complexContent&gt;
     *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
     *       &lt;attribute name="type" use="required" type="{}AllocationConstraintType" /&gt;
     *       &lt;attribute name="nodeA" use="required" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
     *       &lt;attribute name="nodeB" use="required" type="{http://www.w3.org/2001/XMLSchema}string" /&gt;
     *     &lt;/restriction&gt;
     *   &lt;/complexContent&gt;
     * &lt;/complexType&gt;
     * </pre>
     * 
     * 
     */
    @XmlAccessorType(XmlAccessType.FIELD)
    @XmlType(name = "")
    public static class AllocationConstraint {

        @XmlAttribute(name = "type", required = true)
        protected AllocationConstraintType type;
        @XmlAttribute(name = "nodeA", required = true)
        protected String nodeA;
        @XmlAttribute(name = "nodeB", required = true)
        protected String nodeB;

        /**
         * Recupera il valore della proprietà type.
         * 
         * @return
         *     possible object is
         *     {@link AllocationConstraintType }
         *     
         */
        public AllocationConstraintType getType() {
            return type;
        }

        /**
         * Imposta il valore della proprietà type.
         * 
         * @param value
         *     allowed object is
         *     {@link AllocationConstraintType }
         *     
         */
        public void setType(AllocationConstraintType value) {
            this.type = value;
        }

        /**
         * Recupera il valore della proprietà nodeA.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getNodeA() {
            return nodeA;
        }

        /**
         * Imposta il valore della proprietà nodeA.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setNodeA(String value) {
            this.nodeA = value;
        }

        /**
         * Recupera il valore della proprietà nodeB.
         * 
         * @return
         *     possible object is
         *     {@link String }
         *     
         */
        public String getNodeB() {
            return nodeB;
        }

        /**
         * Imposta il valore della proprietà nodeB.
         * 
         * @param value
         *     allowed object is
         *     {@link String }
         *     
         */
        public void setNodeB(String value) {
            this.nodeB = value;
        }

    }

}
