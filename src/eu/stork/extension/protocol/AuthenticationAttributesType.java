//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vJAXB 2.1.10 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.03.04 at 03:48:07 PM CET 
//


package eu.stork.extension.protocol;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for AuthenticationAttributesType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AuthenticationAttributesType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="VIDPAuthenticationAttributes" type="{urn:eu:stork:names:tc:STORK:1.0:protocol}VIDPAuthenticationAttributesType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AuthenticationAttributesType", namespace = "urn:eu:stork:names:tc:STORK:1.0:protocol", propOrder = {
    "vidpAuthenticationAttributes"
})
public class AuthenticationAttributesType {

    @XmlElement(name = "VIDPAuthenticationAttributes")
    protected VIDPAuthenticationAttributesType vidpAuthenticationAttributes;

    /**
     * Gets the value of the vidpAuthenticationAttributes property.
     * 
     * @return
     *     possible object is
     *     {@link VIDPAuthenticationAttributesType }
     *     
     */
    public VIDPAuthenticationAttributesType getVIDPAuthenticationAttributes() {
        return vidpAuthenticationAttributes;
    }

    /**
     * Sets the value of the vidpAuthenticationAttributes property.
     * 
     * @param value
     *     allowed object is
     *     {@link VIDPAuthenticationAttributesType }
     *     
     */
    public void setVIDPAuthenticationAttributes(VIDPAuthenticationAttributesType value) {
        this.vidpAuthenticationAttributes = value;
    }

}
