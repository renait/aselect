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
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * <p>Java class for VIDPAuthenticationAttributesType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="VIDPAuthenticationAttributesType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="CitizenCountryCode" type="{urn:eu:stork:names:tc:STORK:1.0:assertion}CountryCodeType" minOccurs="0"/>
 *         &lt;element name="SPInformation" type="{urn:eu:stork:names:tc:STORK:1.0:protocol}SPInformationType"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "VIDPAuthenticationAttributesType", namespace = "urn:eu:stork:names:tc:STORK:1.0:protocol", propOrder = {
    "citizenCountryCode",
    "spInformation"
})
public class VIDPAuthenticationAttributesType {

    @XmlElement(name = "CitizenCountryCode")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    protected String citizenCountryCode;
    @XmlElement(name = "SPInformation", required = true)
    protected SPInformationType spInformation;

    /**
     * Gets the value of the citizenCountryCode property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getCitizenCountryCode() {
        return citizenCountryCode;
    }

    /**
     * Sets the value of the citizenCountryCode property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setCitizenCountryCode(String value) {
        this.citizenCountryCode = value;
    }

    /**
     * Gets the value of the spInformation property.
     * 
     * @return
     *     possible object is
     *     {@link SPInformationType }
     *     
     */
    public SPInformationType getSPInformation() {
        return spInformation;
    }

    /**
     * Sets the value of the spInformation property.
     * 
     * @param value
     *     allowed object is
     *     {@link SPInformationType }
     *     
     */
    public void setSPInformation(SPInformationType value) {
        this.spInformation = value;
    }

}