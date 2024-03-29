//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, vJAXB 2.1.10 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2016.04.05 at 10:51:53 AM CEST 
//


package eu.stork.extension.assertion;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the eu.stork.extension.assertion package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _SpInstitution_QNAME = new QName("urn:eu:stork:names:tc:STORK:1.0:assertion", "spInstitution");
    private final static QName _CitizenCountryCode_QNAME = new QName("urn:eu:stork:names:tc:STORK:1.0:assertion", "CitizenCountryCode");
    private final static QName _AttributeValue_QNAME = new QName("urn:eu:stork:names:tc:STORK:1.0:assertion", "AttributeValue");
    private final static QName _CountryCodeAddress_QNAME = new QName("urn:eu:stork:names:tc:STORK:1.0:assertion", "countryCodeAddress");
    private final static QName _RequestedAttribute_QNAME = new QName("urn:eu:stork:names:tc:STORK:1.0:assertion", "RequestedAttribute");
    private final static QName _SpSector_QNAME = new QName("urn:eu:stork:names:tc:STORK:1.0:assertion", "spSector");
    private final static QName _SpApplication_QNAME = new QName("urn:eu:stork:names:tc:STORK:1.0:assertion", "spApplication");
    private final static QName _CanonicalResidenceAddress_QNAME = new QName("urn:eu:stork:names:tc:STORK:1.0:assertion", "canonicalResidenceAddress");
    private final static QName _QualityAuthenticationAssuranceLevel_QNAME = new QName("urn:eu:stork:names:tc:STORK:1.0:assertion", "QualityAuthenticationAssuranceLevel");
    private final static QName _SpCountry_QNAME = new QName("urn:eu:stork:names:tc:STORK:1.0:assertion", "spCountry");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: eu.stork.extension.assertion
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link CanonicalResidenceAddressType }
     * 
     */
    public CanonicalResidenceAddressType createCanonicalResidenceAddressType() {
        return new CanonicalResidenceAddressType();
    }

    /**
     * Create an instance of {@link RequestedAttributeType }
     * 
     */
    public RequestedAttributeType createRequestedAttributeType() {
        return new RequestedAttributeType();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link String }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:eu:stork:names:tc:STORK:1.0:assertion", name = "spInstitution")
    public JAXBElement<String> createSpInstitution(String value) {
        return new JAXBElement<String>(_SpInstitution_QNAME, String.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link String }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:eu:stork:names:tc:STORK:1.0:assertion", name = "CitizenCountryCode")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    public JAXBElement<String> createCitizenCountryCode(String value) {
        return new JAXBElement<String>(_CitizenCountryCode_QNAME, String.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link Object }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:eu:stork:names:tc:STORK:1.0:assertion", name = "AttributeValue")
    public JAXBElement<Object> createAttributeValue(Object value) {
        return new JAXBElement<Object>(_AttributeValue_QNAME, Object.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link String }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:eu:stork:names:tc:STORK:1.0:assertion", name = "countryCodeAddress")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    public JAXBElement<String> createCountryCodeAddress(String value) {
        return new JAXBElement<String>(_CountryCodeAddress_QNAME, String.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RequestedAttributeType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:eu:stork:names:tc:STORK:1.0:assertion", name = "RequestedAttribute")
    public JAXBElement<RequestedAttributeType> createRequestedAttribute(RequestedAttributeType value) {
        return new JAXBElement<RequestedAttributeType>(_RequestedAttribute_QNAME, RequestedAttributeType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link String }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:eu:stork:names:tc:STORK:1.0:assertion", name = "spSector")
    public JAXBElement<String> createSpSector(String value) {
        return new JAXBElement<String>(_SpSector_QNAME, String.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link String }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:eu:stork:names:tc:STORK:1.0:assertion", name = "spApplication")
    public JAXBElement<String> createSpApplication(String value) {
        return new JAXBElement<String>(_SpApplication_QNAME, String.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CanonicalResidenceAddressType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:eu:stork:names:tc:STORK:1.0:assertion", name = "canonicalResidenceAddress")
    public JAXBElement<CanonicalResidenceAddressType> createCanonicalResidenceAddress(CanonicalResidenceAddressType value) {
        return new JAXBElement<CanonicalResidenceAddressType>(_CanonicalResidenceAddress_QNAME, CanonicalResidenceAddressType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link Integer }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:eu:stork:names:tc:STORK:1.0:assertion", name = "QualityAuthenticationAssuranceLevel")
    public JAXBElement<Integer> createQualityAuthenticationAssuranceLevel(Integer value) {
        return new JAXBElement<Integer>(_QualityAuthenticationAssuranceLevel_QNAME, Integer.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link String }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:eu:stork:names:tc:STORK:1.0:assertion", name = "spCountry")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    public JAXBElement<String> createSpCountry(String value) {
        return new JAXBElement<String>(_SpCountry_QNAME, String.class, null, value);
    }

}
