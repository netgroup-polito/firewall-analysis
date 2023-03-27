//
// Questo file è stato generato dall'architettura JavaTM per XML Binding (JAXB) Reference Implementation, v2.2.11 
// Vedere <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Qualsiasi modifica a questo file andrà persa durante la ricompilazione dello schema di origine. 
// Generato il: 2023.03.27 alle 01:48:11 PM CEST 
//


package it.polito.verefoo.jaxb;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Classe Java per functionalTypes.
 * 
 * <p>Il seguente frammento di schema specifica il contenuto previsto contenuto in questa classe.
 * <p>
 * <pre>
 * &lt;simpleType name="functionalTypes"&gt;
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string"&gt;
 *     &lt;enumeration value="FIREWALL"/&gt;
 *     &lt;enumeration value="ENDHOST"/&gt;
 *     &lt;enumeration value="ENDPOINT"/&gt;
 *     &lt;enumeration value="ANTISPAM"/&gt;
 *     &lt;enumeration value="CACHE"/&gt;
 *     &lt;enumeration value="DPI"/&gt;
 *     &lt;enumeration value="DPI_S"/&gt;
 *     &lt;enumeration value="MAILCLIENT"/&gt;
 *     &lt;enumeration value="MAILSERVER"/&gt;
 *     &lt;enumeration value="NAT"/&gt;
 *     &lt;enumeration value="VPNACCESS"/&gt;
 *     &lt;enumeration value="VPNEXIT"/&gt;
 *     &lt;enumeration value="WEBCLIENT"/&gt;
 *     &lt;enumeration value="WEBSERVER"/&gt;
 *     &lt;enumeration value="FIELDMODIFIER"/&gt;
 *     &lt;enumeration value="FORWARDER"/&gt;
 *     &lt;enumeration value="LOADBALANCER"/&gt;
 *     &lt;enumeration value="STATEFUL_FIREWALL"/&gt;
 *     &lt;enumeration value="PRIORITY_FIREWALL"/&gt;
 *     &lt;enumeration value="WEB_APPLICATION_FIREWALL"/&gt;
 *     &lt;enumeration value="TRAFFIC_MONITOR"/&gt;
 *   &lt;/restriction&gt;
 * &lt;/simpleType&gt;
 * </pre>
 * 
 */
@XmlType(name = "functionalTypes")
@XmlEnum
public enum FunctionalTypes {

    FIREWALL,
    ENDHOST,
    ENDPOINT,
    ANTISPAM,
    CACHE,
    DPI,
    DPI_S,
    MAILCLIENT,
    MAILSERVER,
    NAT,
    VPNACCESS,
    VPNEXIT,
    WEBCLIENT,
    WEBSERVER,
    FIELDMODIFIER,
    FORWARDER,
    LOADBALANCER,
    STATEFUL_FIREWALL,
    PRIORITY_FIREWALL,
    WEB_APPLICATION_FIREWALL,
    TRAFFIC_MONITOR;

    public String value() {
        return name();
    }

    public static FunctionalTypes fromValue(String v) {
        return valueOf(v);
    }

}
