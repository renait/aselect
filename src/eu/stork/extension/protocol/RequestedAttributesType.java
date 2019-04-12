//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vJAXB 2.1.10 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.03.04 at 03:48:07 PM CET 
//


package eu.stork.extension.protocol;

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for RequestedAttributesType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RequestedAttributesType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{urn:eu:stork:names:tc:STORK:1.0:assertion}RequestedAttribute" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RequestedAttributesType", namespace = "urn:eu:stork:names:tc:STORK:1.0:protocol", propOrder = {
    "requestedAttribute"
})
public class RequestedAttributesType {

    @XmlElement(name = "RequestedAttribute", namespace = "urn:eu:stork:names:tc:STORK:1.0:assertion")
    protected List<RequestedAttributeType> requestedAttribute;

    /**
     * Gets the value of the requestedAttribute property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the requestedAttribute property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRequestedAttribute().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link RequestedAttributeType }
     * 
     * 
     */
    public List<RequestedAttributeType> getRequestedAttribute() {
        if (requestedAttribute == null) {
            requestedAttribute = new ArrayList<RequestedAttributeType>();
        }
        return this.requestedAttribute;
    }

}