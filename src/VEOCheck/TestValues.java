/*
 * Copyright Public Record Office Victoria 2005, 2018
 * Licensed under the CC-BY license http://creativecommons.org/licenses/by/3.0/au/
 * Author Andrew Waugh
 */

package VEOCheck;

/**
 * *************************************************************
 *
 * T E S T V A L U E S
 *
 * This class tests the metadata in a VEO. It prints out the metadata in a flat
 * format (to aid checking) and checks that there are no empty elements.
 *
 * Andrew Waugh Copyright 2005 PROV

* <ul>
 * <li> 9.8.06 Fixed bugs: Did not check that a vers:DateTimeClosed was present
 * in a File VEO; required vers:AgencyIdentifier and vers:SeriesIdentifier to be
 * present in a naa:RelatedRecordId element
 * <li> 14.4.10 Fixed bugs: When testing naa:SchemeType and checking for
 * vers:Subject or vers:Function only went up to the parent node (vers:Title)
 * not the grandparent (vers:RecordMetadata)
 * <li> 11.5.10 Fixed bug: When checking naa:SecurityClassification, only checked
 * the first four assigned values.
 * <li> 27.10.14 Added checking for additional formats in new VERS standard.
  * <li>20150518 Imported into NetBeans.
 * </ul>
 *************************************************************
 */
import java.io.Writer;
import java.util.HashMap;
import java.util.logging.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class TestValues extends TestSupport {

    StringBuffer errorMsg;	// temporary string buffer for error message

    String forceVersion;	// tester is forcing a version
    int layer;                  // this layer of modified or onion VEO
    String thisLayerVersion;    // version according vers:Version
    String thisLayerType;	// type of VEO according to vers:ObjectType
    String originalVEOType;	// original type of VEO according to
                                // the vers:originalVEOType attribute
    boolean inRevisedVEO;	// true if in a vers:RevisedVEO element
    boolean inOriginalVEO;	// true if in a vers:OriginalVEO element
    String schemeType;          // type of title scheme
    String currentContext;	// current context of VEO
    HashMap<String,Node> nodeLabels; // hash table of vers:id 
    
    // Logging
    private final static Logger LOG = Logger.getLogger("VEOCheck.TestValues");
    
    /**
     * Constructor
     *
     * @param verbose
     * @param strict
     * @param da
     * @param oneLayer
     * @param out
     */
    public TestValues(boolean verbose, boolean strict,
            boolean da, boolean oneLayer, Writer out) {
        super(verbose, strict, da, oneLayer, out);
        errorMsg = new StringBuffer();

        forceVersion = null;
        layer = 0;
        thisLayerVersion = null;
        thisLayerType = null;
        originalVEOType = null;
        inRevisedVEO = false;
        inOriginalVEO = false;
        schemeType = null;
        nodeLabels = new HashMap<>();
    }

    /**
     * Return the name of this test
     *
     * @return
     */
    @Override
    public String getName() {
        return "TestValues";
    }

    /**
     * Set the context of testing for invalid values
     *
     * Testing environment is informing class about context of test
     *
     * @param forceVersion force test against a particular version
     */
    public void setContext(String forceVersion) {
        this.forceVersion = forceVersion;
    }

    /**
     * This class tests the metadata in a VEO. It prints out the metadata in a
     * flat format (to aid checking) and checks that there are no empty
     * elements.
     *
     * @param veo the VEO to check
     * @return true if parse suceeded
     */
    public boolean performTest(Element veo) {
        String s;
        Element e;

        // reset globals
        errorMsg.setLength(0);

        success = true;
        forceVersion = null;
        layer = 0;
        thisLayerVersion = null;
        thisLayerType = null;
        originalVEOType = null;
        inRevisedVEO = false;
        inOriginalVEO = false;
        schemeType = null;
        nodeLabels.clear();

        // output test header
        printTestHeader("Testing metadata values\r\n");

        // output metadata contents
        if (verbose) {
            startSubTest("ATTRIBUTE VALUES: The VEO contains the following attributes:");
            s = printAttributes(veo, 1);
            if (s != null) {
                print(s + "\r\n");
            }
            passed("");
            startSubTest("NORMAL VALUES: The VEO contains the following element values:");
            printMetadata(veo, 1);
            print("\r\n");
            passed("");
        }

        // test for empty elements...
        forceVersion = null;
        layer = 0;
        thisLayerVersion = null;
        thisLayerType = null;
        originalVEOType = null;
        inRevisedVEO = false;
        inOriginalVEO = false;
        schemeType = null;
        startSubTest("EMPTY VALUES");
        if (checkForEmptyElements(veo, 1)) {
            passed("The VEO contained no empty elements");
        } else {
            failed("The VEO contained the following empty elements:");
        }

        // check values for validity against specification
        startSubTest("INVALID VALUES");
        labelNodes(veo);
        if (checkInvalidValues(null, veo, 1)) {
            passed("The VEO contained no invalid elements");
        } else {
            failed("The VEO contained the following invalid elements");
        }
        return success;
    }

    /**
     * Print the attributes
     *
     * An element is only printed if it contains an attribute, or one of its
     * children contains an attribute. This is done by generating the print into
     * a string buffer (including any child elements), but only returning it if
     * the element includes an attribute or the child elements do so.
     *
     * This has been separated from the printing the data itself as the
     * resulting display is too complex
     *
     * This test will always do all levels, even if 'oneLevel' is set. This is
     * because you need to know the full structure (e.g. for links between one
     * doc data element and another
     */
    private String printAttributes(Node n, int indent) {
        int i, j;
        Node child;
        NamedNodeMap attrs;
        boolean includeElement;
        StringBuffer sb;
        String s;

        sb = new StringBuffer();
        includeElement = false;

        // node is an element... print element name and then contents
        if (n.getNodeType() == Node.ELEMENT_NODE) {

            // print out element name
            sb.append("\r\n");
            for (i = 0; i < indent; i++) {
                sb.append(' ');
            }
            sb.append("<");
            sb.append(n.getNodeName());

            // process attributes of this element
            attrs = n.getAttributes();
            if (attrs != null) {
                for (i = 0; i < attrs.getLength(); i++) {
                    includeElement = true;
                    child = attrs.item(i);
                    sb.append("\r\n");
                    for (j = 0; j < indent + 2; j++) {
                        sb.append(' ');
                    }
                    sb.append("ATTRIBUTE:");
                    sb.append(child.getNodeName());
                    sb.append("='");
                    sb.append(child.getNodeValue());
                    sb.append("'");
                }
            }

            sb.append("> ");

            // process child elements
            child = n.getFirstChild();
            while (child != null) {
                s = printAttributes(child, indent + 1);
                if (s != null) {
                    includeElement = true;
                    sb.append(s);
                }
                child = child.getNextSibling();
            }

        }
        if (includeElement) {
            s = sb.toString();
        } else {
            s = null;
        }
        return s;
    }

    /**
     * Print the contents of non-empty elements
     *
     * We suppress the values of the base64 encoded elements (signature,
     * certificate, and documentData as these are tested elsewhere.
     *
     * If 'oneLayer' is true it will not recurse inside a vers:DocumentData
     * element (i.e. only check the outermost layer)
     */
    private boolean printMetadata(Node n, int indent) {
        int i;
        Node child;
        String s;
        boolean passed;

        passed = false;

        // node is text... print it unless it is only whitespace
        if (n.getNodeType() == Node.TEXT_NODE) {
            s = n.getNodeValue().trim();
            if (!s.equals("")) {
                print("'" + s + "'");
            }
            passed = true;
        }

        // node is an element... print element name and then contents
        if (n.getNodeType() == Node.ELEMENT_NODE) {

		// suppress empty elements (i.e. things with no value)
            // if (elementIsEmpty(n))
            //	return false;
            // print out element name
            print("\r\n");
            for (i = 0; i < indent; i++) {
                printsp();
            }
            print("<" + n.getNodeName() + "> ");

            // ignore base64 encoded signature or certificate data
            if (n.getNodeName().equals("vers:Certificate")
                    || n.getNodeName().equals("vers:Signature")) {
                print("(value suppressed)");
                return true;
            }

		// for a document data element, suppress the value if it is
            // a normal value, or if it is an onion VEO but only testing
            // one layer
            if (n.getNodeName().equals("vers:DocumentData")) {
                if (!testElementExists(n, "vers:VERSEncapsulatedObject")) {
                    print("(value suppressed)");
                } else if (oneLayer) {
                    print("(only testing one layer)");
                    return true;
                }
            }

		// for a vers:OriginalVEO element, suppress the value if we
            // are only testing one layer
            if (n.getNodeName().equals("vers:OriginalVEO") && oneLayer) {
                print("(only testing one layer)");
                return true;
            }

            // suppress empty elements (i.e. things with no value)
            if (elementIsEmpty(n)) {
                print("****empty****");
            } // otherwise print child elements
            else {
                child = n.getFirstChild();
                if (child == null) {
                    print("!!!!Warning: This element had no children");
                    return false;
                }
                while (child != null) {
                    passed = passed | printMetadata(child, indent + 1);
                    child = child.getNextSibling();
                }
            }
        }
        return passed;
    }

    /**
     * Find empty elements (i.e. elements with no real content). These shouldn't
     * exist, and the test will fail if any are found.
     */
    private boolean checkForEmptyElements(Node n, int indent) {
        int i;
        Node child;
        boolean passed;

        // ignore non element nodes
        if (n.getNodeType() != Node.ELEMENT_NODE) {
            return true;
        }

	// ignore vers:Text elements
	/*
         if (n.getNodeName().equals("vers:Text"))
         return true;
         */
        // ignore vers:DocumentData elements that point to another element
        if (n.getNodeName().equals("vers:DocumentData")) {
            if (findAttribute(n, "vers:forContentSeeElement") != null
                    || findAttribute(n, "vers:forContentsSeeElement") != null
                    || findAttribute(n, "vers:forContentSeeOriginalDocumentAndEncoding") != null
                    || findAttribute(n, "vers:forContentsSeeOriginalDocumentAndEncoding") != null) {
                return true;
            }
        }

        // print element out if it is empty
        if (elementIsEmpty(n)) {
            print("  <" + n.getNodeName() + ">");
            return false;
        }

        // do not check inside onion VEO or originalVEO if oneLayer is set
        if (oneLayer) {
            if (((n.getNodeName().equals("vers:DocumentData"))
                    && testElementExists(n, "vers:VERSEncapsulatedObject"))
                    || n.getNodeName().equals("vers:OriginalVEO")) {
                return true;
            }
        }

        // otherwise check each child
        child = n.getFirstChild();
        passed = true;
        while (child != null) {
            if (!checkForEmptyElements(child, indent + 1)) {
                passed = false;
            }
            child = child.getNextSibling();
        }
        return passed;
    }

    /**
     * Preprocess VEO looking for named nodes (i.e. vers:id) or nodes that
     * should be named
     */
    int docNo; // document number for version 1 vers:Document elements
    int encNo; // encoding number for version 1 vers:Encoding elements

    private void findNames(Node n) {
        int depth;

        // label all nodes
        docNo = 1;
        encNo = 1;
        labelNodes(n);
    }

    /**
     * Label the nodes
     *
     * If the node has a vers:id attribute, use that as the label (i.e. V2
     * elements) For version 1 elements (including those inside modified VEOs),
     * label the V1 vers:DocumentData elements that have real content (i.e. not
     * the outer layers of onion VEOs. The V1 VEOs are labelled as if they were
     * Revision 1 V2 VEOs prefixed by 'v1-' (e.g.
     * 'v1-Revision-1-Document-1-Encoding-1-DocumentData') docNo and encNo are
     * globals that remember the current document/encoding in the current layer
     * of a V1 VEO
     */
    private void labelNodes(Node n) {
        Node child, attr;

        // ignore non element nodes
        if (n.getNodeType() != Node.ELEMENT_NODE) {
            return;
        }

        // if we are going down a level in an onion, reset document number
        if (n.getNodeName().equals("vers:VERSEncapsulatedObject")) {
            docNo = 0;
            encNo = 0;
        }

        // remember a node with a vers:id attribute
        if (n.getNodeName().equals("vers:RevisedVEO")
                || n.getNodeName().equals("vers:SignatureBlock")) {
            attr = findAttribute(n, "vers:id");
            if (attr != null) {
                nodeLabels.put(attr.getNodeValue(), n);
            }
        }
        if (n.getNodeName().equals("vers:Document")) {
            attr = findAttribute(n, "vers:id");
            if (attr != null) {
                nodeLabels.put(attr.getNodeValue(), n);
            } else {
                docNo++;
                encNo = 0;
            }
        }
        if (n.getNodeName().equals("vers:Encoding")) {
            attr = findAttribute(n, "vers:id");
            if (attr != null) {
                nodeLabels.put(attr.getNodeValue(), n);
            } else {
                encNo++;
            }
        }
        if (n.getNodeName().equals("vers:DocumentData")) {
            attr = findAttribute(n, "vers:id");
            if (attr != null) {
                nodeLabels.put(attr.getNodeValue(), n);
            } else if (!testElementExists(n, "vers:VERSEncapsulatedObject")) {
                nodeLabels.put(("v1-Revision-1-Document-" + docNo + "-Encoding-" + encNo + "-DocumentData"), n);
            }
        }

        // go through children
        child = n.getFirstChild();
        while (child != null) {
            labelNodes(child);
            child = child.getNextSibling();
        }
    }

    /**
     * TestSupport elements for controlled values etc
     */
    private boolean checkInvalidValues(Node parent, Node n, int indent) {
        int i;
        Node child;
        boolean passed;

        // check this element
        passed = checkElement(parent, n);

        // do not check inside onion VEO or originalVEO if oneLayer is set
        if (oneLayer) {
            if (((n.getNodeName().equals("vers:DocumentData"))
                    && testElementExists(n, "vers:VERSEncapsulatedObject"))
                    || n.getNodeName().equals("vers:OriginalVEO")) {
                return passed;
            }
        }

        // then check each child
        child = n.getFirstChild();
        while (child != null) {
            if (!checkInvalidValues(n, child, indent + 1)) {
                passed = false;
            }
            child = child.getNextSibling();
        }

        return passed;
    }

    /**
     * Check this element against list of special elements
     */
    static String versNamespace[] = {
        "http://www.prov.vic.gov.au/gservice/standard/pros99007.htm"
    };
    static String naaNamespace[] = {
        "http://www.naa.gov.au/recordkeeping/control/rkms/contents.html"
    };

    private boolean checkElement(Node parent, Node n) {
        // ignore non element nodes
        if (n.getNodeType() != Node.ELEMENT_NODE) {
            return true;
        }

        if (n.getNodeName().equals("vers:VERSEncapsulatedObject")) {
            return testVERSEncapsulatedObject(n);
        }
        if (n.getNodeName().equals("vers:Version")) {
            return testVersion(n);
        }
        if (n.getNodeName().equals("vers:SignatureBlock")) {
            return testSignatureBlock(n);
        }
        if (n.getNodeName().equals("vers:LockSignatureBlock")) {
            return testLockSignatureBlock(n);
        }
        if (n.getNodeName().equals("vers:SignatureAlgorithmIdentifier")) {
            return testSignatureAlgorithmIdentifier(n);
        }
        if (n.getNodeName().equals("vers:SignatureDate")) {
            return testDateValue(n, 136);
        }
        if (n.getNodeName().equals("vers:SignedObject")) {
            return testSignedObject(n);
        }
        if (n.getNodeName().equals("vers:ObjectType")) {
            return testObjectType(n);
        }
        if (n.getNodeName().equals("vers:ObjectContent")) {
            return testObjectContent(n);
        }
        if (n.getNodeName().equals("vers:ObjectCreationDate")) {
            return testDateValue(n, 8);
        }
        if (n.getNodeName().equals("vers:ModifiedVEO")) {
            return testModifiedVEO(n);
        }
        if (n.getNodeName().equals("vers:RevisedVEO")) {
            return testRevisedVEO(n);
        }
        if (n.getNodeName().equals("vers:OriginalVEO")) {
            return testOriginalVEO(n);
        }
        if (n.getNodeName().equals("vers:RecordMetadata")) {
            return testRecordMetadata(n);
        }
        if (n.getNodeName().equals("naa:SecurityClassification")) {
            return testSecurityClassification(n);
        }
        if (n.getNodeName().equals("naa:AccessStatus")) {
            return testAccessStatus(n);
        }
        if (n.getNodeName().equals("naa:SchemeType")) {
            return testSchemeType(n);
        }
        if (n.getNodeName().equals("vers:Subject")) {
            return testSubject(n);
        }
        if (n.getNodeName().equals("vers:AuxiliaryDescription")) {
            return testAuxiliaryDescription(n);
        }
        if (n.getNodeName().equals("naa:RelatedItemId")) {
            return testRelatedItemId(n);
        }
        if (n.getNodeName().equals("vers:Date")) {
            return testVERSDate(n);
        }
        if (n.getNodeName().equals("naa:DateTimeCreated")) {
            return testDateValue(n, 55);
        }
        if (n.getNodeName().equals("naa:DateTimeTransacted")) {
            return testDateValue(n, 56);
        }
        if (n.getNodeName().equals("naa:DateTimeRegistered")) {
            return testDateValue(n, 57);
        }
        if (n.getNodeName().equals("vers:DateTimeClosed")) {
            return testDateValue(n, 144);
        }
        if (n.getNodeName().equals("naa:AggregationLevel")) {
            return testAggregationLevel(n);
        }
        if (n.getNodeName().equals("naa:EventDateTime")) {
            return testDateValue(n, 68);
        }
        if (n.getNodeName().equals("naa:UseDateTime")) {
            return testDateValue(n, 73);
        }
        if (n.getNodeName().equals("naa:UseType")) {
            return testUseType(n);
        }
        if (n.getNodeName().equals("naa:ActionDateTime")) {
            return testDateValue(n, 78);
        }
        if (n.getNodeName().equals("naa:NextActionDue")) {
            return testDateValue(n, 82);
        }
        if (n.getNodeName().equals("naa:DisposalStatus")) {
            return testDisposalStatus(n);
        }
        if (n.getNodeName().equals("naa:RefersTo")) {
            return testRefersTo(n);
        }
        if (n.getNodeName().equals("vers:VEOIdentifier")) {
            return testVEOIdentifier(parent, n);
        }
        if (n.getNodeName().equals("vers:AgencyIdentifier")) {
            return testAgencyIdentifier(n);
        }
        if (n.getNodeName().equals("vers:SeriesIdentifier")) {
            return testSeriesIdentifier(n);
        }
        if (n.getNodeName().equals("naa:DisposalActionDue")) {
            startValueError(n, 3, true);
            Error("Value must be one of: ");
            if (checkValue(n, "Null", " ")) {
                return true;
            }
            return testDateValue(n, 91);
        }
        if (n.getNodeName().equals("vers:OriginatorsCopy")) {
            return testOriginatorsCopy(n);
        }
        if (n.getNodeName().equals("vers:Document")) {
            return testDocument(n);
        }
        if (n.getNodeName().equals("vers:DocumentRightsManagement")) {
            return testDocumentRightsManagement(n);
        }
        // Document Language to do
        if (n.getNodeName().equals("vers:DocumentDate")) {
            return testDateValue(n, 123);
        }
        if (n.getNodeName().equals("vers:DocumentFunction")) {
            return testDocumentFunction(n);
        }
        if (n.getNodeName().equals("vers:Encoding")) {
            return testEncoding(n);
        }
        if (n.getNodeName().equals("vers:FileRendering")) {
            return testFileRendering(n);
        }
        if (n.getNodeName().equals("vers:RenderingKeywords")) {
            return testRenderingKeywords(n);
        }
        if (n.getNodeName().equals("vers:DocumentData")) {
            return testDocumentData(n);
        }
        if (n.getNodeName().equals("vers:DateTimeModified")) {
            return testDateValue(n, 157);
        }
        if (n.getNodeName().equals("vers:DisposalDate")) {
            return testDateValue(n, 147);
        }
        return true;
    }

    /**
     * TestSupport a vers:VERSEncapsulatedObject (10)
     */
    boolean testVERSEncapsulatedObject(Node n) {
        boolean passed = true;
        Node n1;

        // check for moving into an inner layer of V1 onion VEO
        layer++;

	// set version and type for this layer
        // if tester is forcing version of outer layer, over-ride
        // version in vers:Version
        if (forceVersion != null && layer == 1) {
            thisLayerVersion = forceVersion;
        } else {
            n1 = findElement((Element) n, "vers:Version");
            if (n1 == null) {
                startMissingError();
                Error("A vers:VERSEncapsulatedObject (M1) element must contain a vers:Version (M3) element");
                confirmError();
                thisLayerVersion = "Unknown";
                passed = false;
            } else {
                thisLayerVersion = getValue(n1);
            }
        }
        thisLayerType = null;	// don't know yet...

        // test for correct namespace
        if (layer == 1
                && !testAttribute(n, 1, "xmlns:vers", versNamespace)) {
            passed = false;
        }
        if (layer == 1
                && !testAttribute(n, 1, "xmlns:naa", naaNamespace)) {
            passed = false;
        }

	// if v2, check for signature block and at least one lock
        // signature block
        if (thisLayerVersion.equals("2.0")) {
            if (!testElementExists(n, "vers:SignatureBlock")) {
                startV2MissingError();
                Error("A version 2.0 VEO must contain at least one <vers:SignatureBlock> (M134) element");
                confirmError();
                passed = false;
            }
            if (!testElementExists(n, "vers:LockSignatureBlock")) {
                startV2MissingError();
                Error("A version 2.0 VEO must contain at least one <vers:LockSignatureBlock> (M152) element");
                confirmError();
                passed = false;
            }
        }
        return passed;
    }

    /**
     * TestSupport a vers:Version (20)
     */
    boolean testVersion(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError(n, 3, true);
        Error("Value must be one of: ");
        if (!checkValue(n, "1.2", " or ") && !checkValue(n, "2.0", " ")) {
            confirmError();
            passed = false;
        }

	// if tester is forcing version of outer layer, over-ride
        // version in vers:Version
        if (forceVersion != null && layer == 1) {
            thisLayerVersion = forceVersion;
            startValueError(n, 3, true);
            Error("Value must be ");
            if (!checkValue(n, forceVersion, " ")) {
                confirmError();
                passed = false;
            }

            // otherwise, use version in vers:Version as basis of test
        } else {
            thisLayerVersion = getValue(n);
        }
        return passed;
    }

    /**
     * TestSupport a vers:SignatureBlock (30)
     */
    boolean testSignatureBlock(Node n) {
        boolean passed = true;

        // error if version 1 and vers:id attribute present
        if (thisLayerVersion.equals("1.2")
                && findAttribute(n, "vers:id") != null) {
            startV2inV1Error();
            Error("A version 1 <vers:SignatureBlock> (M134) element cannot contain a vers:id attribute");
            confirmError();
            passed = false;
        }

        // error if version 2 and vers:VEOVersion attribute not present
        if (thisLayerVersion.equals("2.0")) {
            passed = checkVersId(n, 134);
        }
        return passed;
    }

    /**
     * TestSupport a vers:LockSignatureBlock (40)
     */
    boolean testLockSignatureBlock(Node n) {
        boolean passed = true;
        String element, id;
        Node attr, n1;
        int i;
        String s[];

        // error if version 1 and lock signature block present
        if (thisLayerVersion.equals("1.2")) {
            startV2inV1Error();
            Error("A version 1 VEO cannot contain a <vers:LockSignatureBlock> (M152) element");
            confirmError();
            passed = false;
        }

        // get vers:signsSignatureBlock attribute node
        attr = findAttribute(n, "vers:signsSignatureBlock");
        if (attr == null) {
            startMissingAttrError();
            Error("A <vers:LockSignatureBlock> (M152) element must contain a vers:signsSignatureBlock attribute");
            confirmError();
            return false;
        }

        // check vers:signsSIgnatureBlock for conformance to pattern
        id = attr.getNodeValue();
        s = id.split("-");
        if (s.length != 4
                || !equals(s[0], "Revision")
                || !testVersIdNumber(s[1])
                || !equals(s[2], "Signature")
                || !testVersIdNumber(s[3])) {
            startAttrError(n, 152, attr, true);
            Error("Attribute value must match the pattern 'Revision-<int>-Signature-<int>'");
            confirmError();
            passed = false;
        }

        // check that vers:signsSignatureBlock points to a vers:SignatureBlock
        n1 = (Node) nodeLabels.get(id);
        if (n1 == null
                || n1.getNodeType() != Node.ELEMENT_NODE
                || !n1.getNodeName().equals("vers:SignatureBlock")) {
            startAttrError(n, 152, attr, true);
            Error("Attribute value does not point to a <vers:SignatureBlock> (M134) element");
            confirmError();
            passed = false;
        }

        return passed;
    }

    /**
     * TestSupport a vers:SignatureAlgorithmIdentifier (50)
     */
    boolean testSignatureAlgorithmIdentifier(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError(n, 150, true);
        Error("Value must be one of: ");
        if (!checkValue(n, "1.2.840.113549.1.1.5", ", ")
                && !checkValue(n, "1.2.840.113549.1.1.11", ", ")
                && !checkValue(n, "1.2.840.113549.1.1.13", " or ")
                && !checkValue(n, "1.2.840.10040.4.3", " ")) {
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:SignedObject (60)
     */
    boolean testSignedObject(Node n) {
        boolean passed = true;
        Node a;
        String s1;

        // error if version 1 and vers:VEOVersion attribute present
        if (thisLayerVersion.equals("1.2")
                && findAttribute(n, "vers:VEOVersion") != null) {
            startV2inV1Error();
            Error("A version 1 <vers:SignedObject> (M4) element cannot contain a vers:VEOVersion attribute");
            confirmError();
            passed = false;
        }

	// error if version 2 and vers:VEOVersion attribute not present
        // or not '2.0'
        if (thisLayerVersion.equals("2.0")) {
            a = findAttribute(n, "vers:VEOVersion");
            if (a == null) {
                startElementError(n, 4);
                Error("A version 2.0 <vers:SignedObject> (M4) must contain a vers:VEOVersion attribute");
                confirmError();
                return false;
            }

            s1 = a.getNodeValue().trim();
            if (!s1.equals("2.0")) {
                startAttrError(n, 4, a, true);
                Error("which must be '2.0' to match <vers:Version> (M3) element");
                confirmError();
                passed = false;
            }
        }
        return passed;
    }

    /**
     * TestSupport a vers:ObjectType (70)
     */
    boolean testObjectType(Node n) {
        boolean passed = true;

        thisLayerType = getValue(n);

        // test for controlled values
        if (thisLayerVersion.equals("1.2")) {
            startValueError(n, 6, true);
            Error("Value must be one of: ");
            if (!checkValue(n, "File", " or ")
                    && !checkValue(n, "Record", " ")) {
                Error("in a version 1 VEO");
                confirmError();
                passed = false;
            }
        }
        if (thisLayerVersion.equals("2.0")) {
            startValueError(n, 6, true);
            Error("Value must be one of: ");
            if (!checkValue(n, "File", ", ")
                    && !checkValue(n, "Record", " or ")
                    && !checkValue(n, "Modified VEO", " ")) {
                Error("in a version 2 VEO");
                confirmError();
                passed = false;
            }
            if (inRevisedVEO
                    && !equals(originalVEOType, getValue(n))) {
                startValueError(n, 6, true);
                Error("The value of the <vers:ObjectType> (M6) element in a <vers:RevisedVEO> (M158) element must match the value of the vers:OriginalVEOType attribute in the <vers:ModifiedVEO> (M156) element (which was " + originalVEOType + ")");
                confirmError();
                inRevisedVEO = false;
                passed = false;
            }
            if (inOriginalVEO
                    && !(equals(originalVEOType, getValue(n))
                    || equals("Modified VEO", getValue(n)))) {
                startValueError(n, 6, true);
                Error("The value of the <vers:ObjectType> (M6) element in a <vers:OriginalVEO> (M159) element must match the value of the vers:OriginalVEOType attribute in the <vers:ModifiedVEO> (M156) element (which was " + originalVEOType + ") or be 'Modified VEO'");
                confirmError();
                inOriginalVEO = false;
                passed = false;
            }
        }
        return passed;
    }

    /**
     * TestSupport a vers:ObjectContent (80)
     */
    boolean testObjectContent(Node n) {
        boolean passed = true;

        if (equals(thisLayerType, "File")
                && !testElementExists(n, "vers:File")) {
            startError(3, "Error in value of element <vers:ObjectContent> (M9).");
            Error("The value of the <vers:ObjectType> (M6) element is 'File' but the <vers:ObjectContent> (M9) element does not contain a <vers:File> (M142) element");
            confirmError();
            passed = false;
        }
        if (equals(thisLayerType, "Record")
                && !testElementExists(n, "vers:Record")) {
            startError(3, "Error in value of element <vers:ObjectContent> (M9).");
            Error("The value of the <vers:ObjectType> (M6) element is 'Record' but the <vers:ObjectContent> (M9) element does not contain a <vers:Record> (M10) element");
            confirmError();
            passed = false;
        }
        if (equals(thisLayerType, "Modified VEO")
                && !testElementExists(n, "vers:ModifiedVEO")) {
            startError(3, "Error in value of element <vers:ObjectContent> (M9).");
            Error("The value of the <vers:ObjectType> (M6) element is 'Modified VEO' but the <vers:ObjectContent> (M9) element does not contain a <vers:ModifiedVEO> (M156) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:ModifiedVEO (90)
     */
    boolean testModifiedVEO(Node n) {
        boolean passed = true;
        String s;
        Node attr;

        // remember value of vers:OriginalVEOType
        s = originalVEOType;
        attr = findAttribute(n, "vers:OriginalVEOType");
        if (attr == null) {
            startMissingAttrError();
            Error("A <vers:ModifiedVEO> (M156) element must contain a vers:OriginalVEOType attribute");
            confirmError();
            originalVEOType = "Unknown";
            passed = false;
        } else {
            originalVEOType = attr.getNodeValue();
        }

        // check for valid values of vers:OriginalVEOType attribute
        if (!equals(originalVEOType, "File")
                && !equals(originalVEOType, "Record")) {
            startAttrError(n, 156, attr, true);
            Error("The value of the vers:OriginalVEOType attribute within a <vers:ModifiedVEO> (M156) element must be either 'File' or 'Record'");
            confirmError();
            passed = false;
        }

	// second and later vers:ModifiedVEO elements must have the same
        // value as the first
        if (s != null && !equals(originalVEOType, s)) {
            startAttrError(n, 156, attr, true);
            Error("An inner <vers:ModifiedVEO> (M156) element has a vers:OriginalVEOType attribute with the value (" + s + ") that does not match the type of the outermost <vers:ModifiedVEO> (M156) element (which was '" + originalVEOType + "')");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:RevisedVEO (100)
     */
    boolean testRevisedVEO(Node n) {
        boolean passed = true;

        inRevisedVEO = true;
        inOriginalVEO = false;
        if (findAttribute(n, "vers:id") == null) {
            startMissingAttrError();
            Error("A <vers:RevisedVEO> (M158) element must contain a vers:id attribute");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:OriginalVEO (110)
     */
    boolean testOriginalVEO(Node n) {
        boolean passed = true;
        Node n1;

        inOriginalVEO = true;
        inRevisedVEO = false;
        layer++;

        // reset type for this layer
        thisLayerType = null;

        // set version for this layer
        n1 = findElement((Element) n, "vers:Version");
        if (n1 == null) {
            startV2MissingError();
            Error("A <vers:OriginalVEO> (M159) element must contain a <vers:Version> (M3) element");
            confirmError();
            thisLayerVersion = "Unknown";
            passed = false;
        } else {
            thisLayerVersion = getValue(n1);
        }
        return passed;
    }

    /**
     * TestSupport a vers:RecordMetadata (120)
     */
    boolean testRecordMetadata(Node n) {
        boolean passed = true;
        if (thisLayerVersion.equals("1.2")
                && !testElementExists(n, "naa:RecordIdentifier")) {
            startV1MissingError();
            Error("In a version 1 VEO, a <vers:RecordMetadata> (M11) element must contain a <naa:RecordIdentifier> (M65) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:SecurityClassification (130)
     * 20191209 - Added the classifications Unofficial to Personal Privacy
     */
    boolean testSecurityClassification(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError(n, 25, true);
        Error("which must be: ");
        if (!checkValue(n, "Unclassified", ", ")
                && !checkValue(n, "In-Confidence", ", ")
                && !checkValue(n, "Protected", ", ")
                && !checkValue(n, "Highly Protected", ", ")
                && !checkValue(n, "Restricted", ", ")
                && !checkValue(n, "Confidential", ", ")
                && !checkValue(n, "Secret", ", ")
                && !checkValue(n, "Top Secret", ", ")
                && !checkValue(n, "Unofficial", ", ")
                && !checkValue(n, "OFFICIAL", ", ")
                && !checkValue(n, "OFFICIAL:Sensitive", ", ")
                && !checkValue(n, "Cabinet-in-Confidence", ", ")
                && !checkValue(n, "Legal Privilege", ", ")
                && !checkValue(n, "Legislative Secrecy", ", or ")
                && !checkValue(n, "Personal Privacy", " ")) {
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a naa:AccessStatus (140)
     */
    boolean testAccessStatus(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError(n, 29, true);
        Error("Value must be one of: ");
        if (!checkValue(n, "Not for Release", ", ")
                && !checkValue(n, "May be Published", ", ")
                && !checkValue(n, "May be Released under FOI", ", ")
                && !checkValue(n, "Limited Release", " or ")
                && !checkValue(n, "Published", " ")) {
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a naa:SchemeType (150)
     */
    boolean testSchemeType(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError(n, 33, true);
        Error("Value must be one of: ");
        if (!checkValue(n, "Functional", ", ")
                && !checkValue(n, "Subject-based", " or ")
                && !checkValue(n, "Free Text", " ")) {
            confirmError();
            passed = false;
        }

        // Check that VEO has appropriate titling mechanism
        if (equals(getValue(n), "Subject-based")
                && !testElementExists(n.getParentNode().getParentNode(), "vers:Subject")) {
            startValueError(n, 33, false);
            Error("has the value 'Subject-based', but VEO does not contain a <vers:Subject> (M37) element");
            confirmError();
            passed = false;
        }
        if (equals(getValue(n), "Funtional")
                && !testElementExists(n.getParentNode().getParentNode(), "vers:Function")) {
            startValueError(n, 33, false);
            Error("has the value 'Functional', but VEO does not contain a <vers:Function> (M50) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:Subject (160)
     */
    boolean testSubject(Node n) {
        boolean passed = true;

        if (!testElementExists(n, "vers:Keyword")) {
            startElementError(n, 37);
            Error("A <vers:Subject> (M37) element must contain at least one <vers:Keyword> (M39) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:AuxiliaryDescription (170)
     */
    boolean testAuxiliaryDescription(Node n) {
        boolean passed = true;

        // error if present in a version 1 VEO
        if (thisLayerVersion.equals("1.2")) {
            startV2inV1Error();
            Error("A version 1 VEO cannot contain a <vers:AuxiliaryDescription> (M153) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a naa:RelatedItemId (180)
     */
    boolean testRelatedItemId(Node n) {
        boolean passed = true;

        if (thisLayerVersion.equals("2.0")
                && !testElementExists(n, "vers:VEOIdentifier")) {
            startV2MissingError();
            Error("In version 2.0, a <vers:RelatedItemId> (M43) element must contain a <vers:VEOIdentifier> (M99) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:Date (185)

 ajw 9/8/06. Method added to ensure that vers:DateTimeClosed is present in
     * a file VEO.
     */
    boolean testVERSDate(Node n) {
        boolean passed = true;

        if (!testElementExists(n, "vers:DateTimeClosed")) {
            startV2MissingError();
            Error("In a File VEO, a <vers:Date> (M54) element must contain a <vers:DateTimeClosed> (M144) element when submitted to PROV");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a naa:AggregationLevel (190)
     */
    boolean testAggregationLevel(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError(n, 59, true);
        Error("Value must be one of: ");
        if (!checkValue(n, "File", " or ") && !checkValue(n, "Item", " ")) {
            confirmError();
            passed = false;
        }
        if (equals(thisLayerType, "File")
                && !equals(getValue(n), "File")) {
            startValueError(n, 59, true);
            Error("The value of the <naa:AggregationLevel> (M159) element (which is " + getValue(n) + ") must be 'File' to match the content of the enclosing <vers:ObjectType> (M6) element");
            confirmError();
            passed = false;
        }
        if (equals(thisLayerType, "Record")
                && !equals(getValue(n), "Item")) {
            startValueError(n, 59, true);
            Error("The value of the <naa:AggregationLevel> (M159) element (which is " + getValue(n) + ") must be 'Item' as the value of the <vers:ObjectType> (M6) element is 'Record'");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a naa:UseType (200)
     */
    boolean testUseType(Node n) {
        boolean passed = true;

        // test for controlled values
        if (!strict) {
            return true;
        }
        startValueError(n, 74, true);
        Error("Value must be one of: ");
        if (!checkValue(n, "Listed", ", ")
                && !checkValue(n, "Metadata Accessed", ", ")
                && !checkValue(n, "Content Accessed", ", ")
                && !checkValue(n, "Illegally Accessed", ", ")
                && !checkValue(n, "Booked", ", ")
                && !checkValue(n, "Copied", ", ")
                && !checkValue(n, "Downloaded", ", ")
                && !checkValue(n, "Screen Dumped", ", ")
                && !checkValue(n, "Viewed", " or ")
                && !checkValue(n, "Security Breached", " ")) {
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a naa:DisposalStatus (210)
     */
    boolean testDisposalStatus(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError(n, 92, true);
        Error("Value must be one of: ");
        if (!checkValue(n, "Permanent", ", ")
                && !checkValue(n, "Temporary", " or ")
                && !checkValue(n, "Unknown", " ")) {
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a naa:RefersTo (220)
     */
    boolean testRefersTo(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError(n, 95, true);
        Error("Value must be one of: ");
        if (!checkValue(n, "Creation", ", ")
                && !checkValue(n, "Retention", ", ")
                && !checkValue(n, "Access/Usage", ", ")
                && !checkValue(n, "Accessibility", " or ")
                && !checkValue(n, "Record Quality", " ")) {
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:VEOIdentifier (230)

 ajw 9/8/06 doesn't test for vers:AgencyIdentifier and
 vers:SeriesIdentifier if in a naa:RelatedItemId. Required adding context
     * (parent) node.
     */
    boolean testVEOIdentifier(Node parent, Node n) {
        boolean passed = true;
        if (!parent.getNodeName().equals("naa:RelatedItemId")
                && !testElementExists(n, "vers:AgencyIdentifier")) {
            startMissingError();
            Error("A <vers:VEOIdentifier> (M99) element must contain a <vers:AgencyIdentifier> (M100) element when submitted to PROV");
            confirmError();
            passed = false;
        }
        if (!parent.getNodeName().equals("naa:RelatedItemId")
                && !testElementExists(n, "vers:SeriesIdentifier")) {
            startMissingError();
            Error("A <vers:VEOIdentifier> (M99) element must contain a <vers:SeriesIdentifier> (M101) element when submitted to PROV");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:AgencyIdentifier (240)
     */
    boolean testAgencyIdentifier(Node n) {
        boolean passed = true;
        String s;

        s = getValue(n).trim();
        try {
            Integer.parseInt(s);
        } catch (NumberFormatException nfe) {
            startValueError(n, 100, true);
            Error("Value must be the VA number (without leading 'VA')");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:SeriesIdentifier (250)
     */
    boolean testSeriesIdentifier(Node n) {
        boolean passed = true;
        String s;

        s = getValue(n).trim();
        try {
            Integer.parseInt(s);
        } catch (NumberFormatException nfe) {
            startValueError(n, 101, true);
            Error("Value must be the VPRS number (without leading 'VPRS')");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:OriginatorsCopy (260)
     */
    boolean testOriginatorsCopy(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError(n, 109, true);
        Error("Value must be one of: ");
        if (!checkValue(n, "true", " or ")
                && !checkValue(n, "false", " ")) {
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:Document (270)

 The source for the MIME types is the official IANA list
 http://www.iana.org/assignments/media-types/media-types.xhtml#text, which
 has been checked against the Library of Congress files type information
 http://www.digitalpreservation.gov/formats
     */
    boolean testDocument(Node n) {
        boolean passed = true;
        String s, ids[];
        Node attr, n1;
        boolean foundSubDocAttr;
        int i, j;
        NodeList nl;
        String fmt[];
        boolean foundLtpf;
        StringBuffer fmtsFound;

	// test to see if Document contains a valid long term preservation
        // format encoding
        nl = ((Element) n).getElementsByTagName("vers:RenderingKeywords");
        foundLtpf = false;
        fmtsFound = new StringBuffer();
        for (i = 0; i < nl.getLength(); i++) {
            n1 = (Element) nl.item(i);
            s = getValue(n1).trim().toLowerCase();
            fmtsFound.append(s);
            if (s.contains(".pdf")
                    || s.contains("application/pdf")
                    || s.contains(".txt")
                    || s.contains("text/plain") ||
                    s.contains(".doc")
                    || s.contains("application/msword") ||
                    s.contains(".docx")
                    || s.contains("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
                    || s.contains(".htm")
                    || s.contains(".html")
                    || s.contains("text/html") || // IANA media-types
                    // IANA media-types
                    s.contains(".xml")
                    || s.contains("text/xml") || // IANA media-types, see LOC
                    // IANA media-types, see LOC
                    s.contains("application/xml") || // IANA media-types
                    s.contains("application/xhtml+xml") || // IANA media-types
                    s.contains("application/xhtml-dtd") || // IANA media-types
                    s.contains(".css")
                    || s.contains("text/css") || // IANA media-types
                    s.contains(".warc")
                    || s.contains("application/warc") || // appears to be unofficial
                    s.contains(".csv")
                    || s.contains("text/csv") || // IANA media-types
                    s.contains(".xls")
                    || s.contains("application/vnd.ms-excel") || // IANA media-types
                    s.contains(".xlsx")
                    || s.contains("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                    || s.contains(".ppt")
                    || s.contains("application/vnd.ms-powerpoint") || // IANA media-types
                    s.contains(".pptx")
                    || s.contains("application/vnd.openxmlformats-officedocument.presentationml.presentation")
                    || s.contains(".tif")
                    || s.contains(".tiff")
                    || s.contains("image/tiff") || // IANA media-types
                    s.contains(".jpg")
                    || s.contains(".jpeg")
                    || s.contains("image/jpeg") || // IANA media-types - not official, but see RFC 2046
                    s.contains(".jp2")
                    || s.contains("image/jp2") || // IANA media-types
                    s.contains(".mp3")
                    || s.contains("audio/mpeg4-generic") || // IANA media-types
                    // IANA media-types
                    s.contains("audio/mpeg") || // IANA media-types, note mp3 is not official
                    // IANA media-types, note mp3 is not official
                    s.contains(".mp4")
                    || s.contains(".wav") || // no offical IANA media type
                    // no offical IANA media type
                    s.contains("video/mpeg") || // IANA media-types
                    // IANA media-types
                    s.contains("video/mp4") || // IANA media-types
                    // IANA media-types
                    s.contains(".eml")
                    || s.contains("message/rfc822")) {
                foundLtpf = true;
                break;
            }
        }
        if (!foundLtpf) {
            startError(10, "Document without Long Term Preservation Format");
            Error("A <Document> (M114) element must contain an <Encoding> (M126) element with a valid long term preservation format for acceptance into the digital archive. ");
            if (nl.getLength() == 0) {
                Error("The Document has no <vers:RenderingKeywords> (M132) elements and so no long term preservation formats can be identified");
            } else {
                Error("Formats found in this Document are: " + fmtsFound.toString());
            }
            confirmError();
            passed = false;
        }

        // test for attributes in V1 VEOs
        if (thisLayerVersion.equals("1.2")) {
            if (findAttribute(n, "vers:id") != null) {
                startV2inV1Error();
                Error("In a version 1 VEO, a <vers:Document> (M114) element cannot contain a vers:id attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:subordinateDocuments") != null) {
                startV2inV1Error();
                Error("In a version 1 VEO, a <vers:Document> (M114) element cannot contain a vers:subordinateDocuments attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:subordinateDocumentRelationship") != null) {
                startV2inV1Error();
                Error("In a version 1 VEO, a <vers:Document> (M114) element cannot contain a vers:subordinateDocumentRelationship attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:parentDocument") != null) {
                startV2inV1Error();
                Error("In a version 1 VEO, a <vers:Document> (M114) element cannot contain a vers:parentDocument attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:presentThisDocument") != null) {
                startV2inV1Error();
                Error("In a version 1 VEO, a <vers:Document> (M114) element cannot contain a vers:presentThisDocument attribute");
                confirmError();
                passed = false;
            }
            if (!testElementExists(n, "vers:Encoding")) {
                startV1MissingError();
                Error("In a version 1 VEO, a <vers:Document> (M114) element must contain at least one <vers:Encoding> element");
                confirmError();
                passed = false;
            }
            return passed;
        }

	// the following tests are performed for version 2
        // check version id attribute
        if (!checkVersId(n, 114)) {
            passed = false;
        }

        // test for valid vers:subordinateDocuments
        attr = findAttribute(n, "vers:subordinateDocuments");
        foundSubDocAttr = false;
        if (attr != null) {
            foundSubDocAttr = true;
            ids = attr.getNodeValue().split(" ");
            for (i = 0; i < ids.length; i++) {
                n1 = (Node) nodeLabels.get(attr.getNodeValue());
                if (n1 == null
                        || n1.getNodeType() != Node.ELEMENT_NODE
                        || !n1.getNodeName().equals("vers:Document")) {
                    startAttrError(n, 114, attr, true);
                    Error("The vers:subordinateDocuments attribute (value '" + ids[i] + "') does not point to a <vers:Document> (M114) element");
                    confirmError();
                    passed = false;
                }
                if (n == n1) {
                    startAttrError(n, 114, attr, true);
                    Error("The vers:subordinateDocuments attribute (value '" + ids[i] + "') points to this <vers:Document> (M114) element");
                    confirmError();
                    passed = false;
                }
            }
        }

        // test for valid vers:subordinateDocumentRelationship
        attr = findAttribute(n, "vers:subordinateDocumentRelationship");
        if (attr != null) {
            s = attr.getNodeValue();
            if (!s.equals("Sequence")
                    && !s.equals("Set")
                    && !s.equals("Alternative")) {
                startAttrError(n, 114, attr, true);
                Error("The vers:subordinateDocumentRelationship attribute must have the value 'Sequence', 'Set' or 'Alternative'");
                confirmError();
                passed = false;
            }
        }

        // test for valid vers:presentThisDocument
        attr = findAttribute(n, "vers:presentThisDocument");
        if (attr != null) {
            s = attr.getNodeValue();
            if (!s.equals("true")
                    && !s.equals("false")) {
                startAttrError(n, 114, attr, true);
                Error("The vers:presentThisDocument attribute must have the value 'true', or 'false'");
                confirmError();
                passed = false;
            }
        }

        if (!foundSubDocAttr && !testElementExists(n, "vers:Encoding")) {
            startV2MissingError();
            Error("A version 2 <vers:Document> (M114) element must either contain <vers:Encoding> (M126) elements or a vers:subordinateDocuments attribute");
            passed = false;
        }

        return passed;
    }

    /**
     * Check a format from a vers:RenderingKeyword element against an approved
     * list THIS METHOD IS NOT USED
     */
    static String[] validFormats = {".pdf", ".tif", ".tiff", ".jpg", ".txt",
        ".jp2", ".mp4",
        "text/plain", "image/tiff", "image/jpeg",
        "image/jp2", "video/mp4", "video/mpeg",
        "application/pdf"};

    boolean testFormat(String s) {
        int i;

        s = s.toLowerCase();
        for (i = 0; i < validFormats.length; i++) {
            if (equals(validFormats[i], s)) {
                return true;
            }
        }
        return false;
    }

    /**
     * TestSupport a vers:DocumentRightsManagement (280)
     */
    boolean testDocumentRightsManagement(Node n) {
        boolean passed = true;

        // error if version 1 and document function present
        if (thisLayerVersion.equals("1.2")) {
            startV2inV1Error();
            Error("A version 1 VEO cannot contain a <vers:DocumentRightsManagement> (M154) element ");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:DocumentFunction (290)
     */
    boolean testDocumentFunction(Node n) {
        boolean passed = true;

        // error if version 1 and document function present
        if (thisLayerVersion.equals("1.2")) {
            startV2inV1Error();
            Error("A version 1 VEO cannot contain a <vers:DocumentFunction> (M155) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:Encoding (300)
     */
    boolean testEncoding(Node n) {
        boolean passed = true;

        if (thisLayerVersion.equals("1.2")
                && findAttribute(n, "vers:id") != null) {
            startV2inV1Error();
            Error("A version 1 <vers:Encoding> (M126) element cannot contain a vers:id attribute");
            confirmError();
            passed = false;
        }
        if (thisLayerVersion.equals("2.0") && !checkVersId(n, 126)) {
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:FileRendering (310)
     */
    boolean testFileRendering(Node n) {
        boolean passed = true;

        if (!testElementExists(n, "vers:RenderingKeywords")) {
            startMissingError();
            Error("A <vers:RenderingKeywords> (M132) element must be present in each <vers:Encoding> (M126) element to allow automated extraction");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Check the rendering keywords (320) This function breaks up the value into
     * the format keywords, then calls validFormat() to determine if the
     * keywords are valid. The syntax of the value is '<ft>[; <ft>]*' where ft
     * is .<ext>|<mime>
     */
    boolean testRenderingKeywords(Node n) {
        String s;
        boolean passed = true;
        String fmt[];
        int i;

        startValueError(n, 132, true);
        s = getValue(n).trim();
        if (s == null || s.length() == 0) { //empty elements picked up elsewhere
            return false;
        }

        if (s.charAt(0) != '\'') {
            if (strict) {
                Error("Value must start with quote (')");
                passed = false;
            }
        } else {
            s = s.substring(1, s.length());
        }
        if (s == null || s.length() == 0) {
            Error("    Value is empty");
            passed = false;
        }
        if (s.charAt(s.length() - 1) != '\'') {
            if (strict) {
                Error("Value must end with quote (')");
                passed = false;
            }
        } else {
            s = s.substring(0, s.length() - 1);
        }
        if (s == null || s.length() == 0) {
            Error("Value is empty");
            passed = false;
        }
        if (!passed) {
            confirmError();
        }
        return passed;
    }

    /**
     * TestSupport a vers:DocumentData (330)
     */
    boolean testDocumentData(Node n) {
        boolean passed = true;

        // test for attributes in V1
        if (thisLayerVersion.equals("1.2")) {
            if (findAttribute(n, "vers:id") != null) {
                startV2inV1Error();
                Error("In a version 1 VEO, a <vers:DocumentData> (M133) element cannot contain a vers:id attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:forContentsSeeElement") != null) {
                startV2inV1Error();
                Error("In a version 1 VEO, a <vers:DocumentData> (M133) element cannot contain a vers:forContentsSeeElement attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:forContentSeeElement") != null) {
                startV2inV1Error();
                Error("In a version 1 VEO, a <vers:DocumentData> (M133) element cannot contain a vers:forContentSeeElement attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:forContentsSeeOriginalDocumentAndEncoding") != null) {
                startV2inV1Error();
                Error("In a version 1 VEO, a <vers:DocumentData> (M133) element cannot contain a vers:forContentsSeeOriginalDocumentAndEncoding attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:forContentSeeOriginalDocumentAndEncoding") != null) {
                startV2inV1Error();
                Error("In a version 1 VEO, a <vers:DocumentData> (M133) element cannot contain a vers:forContentSeeOriginalDocumentAndEncoding attribute");
                confirmError();
                passed = false;
            }
            return passed;
        }

        // check for valid version id...
        if (!checkVersId(n, 133)) {
            passed = false;
        }

        // check that a link points to a valid vers:DocumentData
        passed &= checkLink(n, "vers:forContentSeeElement");
        passed &= checkLink(n, "vers:forContentsSeeElement");
        passed &= checkLink(n, "vers:forContentSeeOriginalDocumentAndEncoding");
        passed &= checkLink(n, "vers:forContentsSeeOriginalDocumentAndEncoding");

        return passed;
    }

    /**
     * TestSupport a link from one vers:DocumentData to another
     */
    private boolean checkLink(Node n, String name) {
        Node attr, n1;
        boolean passed = true;
        boolean v1link = false;
        String id;

        // get attribute value
        attr = findAttribute(n, name);
        if (attr != null) {

            // if link is to a version 1 VEO prepend 'v1-'
            if (name.equals("vers:forContentSeeOriginalDocumentAndEncoding")
                    || name.equals("vers:forContentsSeeOriginalDocumentAndEncoding")) {
                v1link = true;
                id = "v1-" + attr.getNodeValue();
            } else {
                v1link = false;
                id = attr.getNodeValue();
            }

            // document data must not contain a link and document data
            if (n.getFirstChild() != null) {
                startElementError(n, 133);
                Error("A <vers:DocumentData> (M133) element cannot contain both content and a link (" + name + ") to another <vers:DocumentData> (M133) element");
                confirmError();
                passed = false;
            }

            // find the linked element
            n1 = (Node) nodeLabels.get(id);
            if (n1 == null) {
                startAttrError(n, 133, attr, true);
                Error("Attribute does not reference another element");
                confirmError();
                return false;
            }

            // linked element must by a vers:DocumentData
            if (n1.getNodeType() != Node.ELEMENT_NODE
                    || !n1.getNodeName().equals("vers:DocumentData")) {
                startAttrError(n, 133, attr, true);
                Error("Attribute does not reference another <vers:DocumentData> (M133) element");
                confirmError();
                passed = false;
            }

            // linked document data element must contain actual data
            if (n1.getFirstChild() == null) {
                startAttrError(n, 133, attr, true);
                Error("Attribute references a <vers:DocumentData> (M133) without content");
                confirmError();
                passed = false;
            }
        }
        return passed;
    }

    /**
     * Check the value in the node against the required value If test fails, add
     * required value as an option in the error message If strict, check case,
     * otherwise ignore case
     */
    boolean checkValue(Node n, String value, String separator) {
        String s1;

        Error("'" + value + "'" + separator);
        if (strict) {
            s1 = getValue(n).trim();
        } else {
            value = value.toLowerCase();
            s1 = getValue(n).trim().toLowerCase();
        }
        return value.equals(s1);
    }

    /**
     * Compare the two values If strict, compare case, otherwise ignore case
     */
    boolean equals(String s1, String s2) {
        if (!strict) {
            s1 = s1.toLowerCase();
            s2 = s2.toLowerCase();
        }
        return s1.equals(s2);
    }

    /**
     * TestSupport to see if an element has at least one immediate subordinate of the
 specified type
     *
     * @param element	the element node to be searched
     * @param name	the name of the element to be found
     */
    boolean testElementExists(Node element, String name) {
        Node n;

        // look for specified element
        n = element.getFirstChild();
        while (n != null) {
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && n.getNodeName().equals(name)) {
                return true;
            }
            n = n.getNextSibling();
        }

        // didn't find it
        return false;
    }

    /**
     * TestSupport to see if an attribute has a specified value

 An error is raised if the attribute is not found, or if it does not have
 one of the valid values
     *
     * @param n	the element node the attribute is to be found in
     * @param name	the name of the attribute to find
     * @param id	the VERS specification number for the element
     * @param validvalues	an array of valid values for this attribute
     * @result false if the test failed (i.e. error raised)
     */
    boolean testAttribute(Node n, int id, String name, String[] validvalues) {
        Node a;
        int i;
        String s1, s2;

        // try to find attribute in node
        a = findAttribute(n, name);
        if (a == null) {
            startElementError(n, id);
            Error("   Element must contain a " + name + " attribute");
            confirmError();
            return false;
        }

        // try to find attribute value in list of valid values
        startAttrError(n, id, a, true);
        Error("    which must be: ");
        for (i = 0; i < validvalues.length; i++) {
            if (strict) {
                s1 = a.getNodeValue().trim();
                s2 = validvalues[i];
            } else {
                s1 = a.getNodeValue().trim().toLowerCase();
                s2 = validvalues[i].toLowerCase();
            }
            if (s1.equals(s2)) {
                return true;
            }
            Error("'" + validvalues[i] + "' ");
            if (i == validvalues.length - 2) {
                Error("or ");
            }
        }
        confirmError();
        return false;
    }

    /**
     * Check a vers:id attribute
     *
     * If v1.2, vers:id attribute must not be present if v2, vers:id attribute
     * must be present and must match standard pattern
     *
     * @param n the element in which the id must be found
     * @param mno the VERS specification number for the element (M number)
     */
    boolean checkVersId(Node n, int mno) {
        String element, id;
        Node attr;
        int i;
        String s[];

        element = n.getNodeName();

        // get vers:id attribute node
        attr = findAttribute(n, "vers:id");

        // error if version 1 and vers:id attribute present
        if (thisLayerVersion.equals("1.2") && attr != null) {
            startV2inV1Error();
            Error("<" + element + "> cannot contain a vers:id attribute in a version 1 VEO");
            confirmError();
            return false;
        }

        // finished test if version 1...
        if (thisLayerVersion.equals("1.2")) {
            return true;
        }

        // error if version 2 and vers:id attribute not present
        if (thisLayerVersion.equals("2.0") && attr == null) {
            startMissingAttrError();
            Error("<" + element + "> must contain a vers:id attribute in a version 2 VEO");
            confirmError();
            return false;
        }

        // check vers:id for conformance to pattern
        id = attr.getNodeValue();
        startAttrError(n, mno, attr, true);
        Error("The value ");
        s = id.split("-");
        if (element.equals("vers:RevisedVEO")) {
            if (s.length != 2
                    || !equals(s[0], "Revision")
                    || !testVersIdNumber(s[1])) {
                Error("must match 'Revision-<int>'");
                confirmError();
                return false;
            }
        }
        if (element.equals("vers:SignatureBlock")) {
            if (s.length != 4
                    || !equals(s[0], "Revision")
                    || !testVersIdNumber(s[1])
                    || !equals(s[2], "Signature")
                    || !testVersIdNumber(s[3])) {
                Error("must match 'Revision-<int>-Signature-<int>'");
                confirmError();
                return false;
            }
        }
        if (element.equals("vers:Document")) {
            if (s.length != 4
                    || !equals(s[0], "Revision")
                    || !testVersIdNumber(s[1])
                    || !equals(s[2], "Document")
                    || !testVersIdNumber(s[3])) {
                Error("must match 'Revision-<int>-Document-<int>'");
                confirmError();
                return false;
            }
        }
        if (element.equals("vers:Encoding")) {
            if (s.length != 6
                    || !equals(s[0], "Revision")
                    || !testVersIdNumber(s[1])
                    || !equals(s[2], "Document")
                    || !testVersIdNumber(s[3])
                    || !equals(s[4], "Encoding")
                    || !testVersIdNumber(s[5])) {
                Error("must match 'Revision-<int>-Document-<int>- Encoding-<int>'");
                confirmError();
                return false;
            }
        }
        if (element.equals("vers:DocumentData")) {
            if (s.length != 7
                    || !equals(s[0], "Revision")
                    || !testVersIdNumber(s[1])
                    || !equals(s[2], "Document")
                    || !testVersIdNumber(s[3])
                    || !equals(s[4], "Encoding")
                    || !testVersIdNumber(s[5])
                    || !equals(s[6], "DocumentData")) {
                Error("must match 'Revision-<int>-Document-<int>- Encoding-<int>-DocumentData'");
                confirmError();
                return false;
            }
        }
        return true;
    }

    /**
     * TestSupport to see if a string contains a number
     */
    boolean testVersIdNumber(String s) {
        try {
            Integer.parseInt(s);
        } catch (NumberFormatException nfe) {
            return false;
        }
        return true;
    }

    /**
     * Check a date value against a date pattern date pattern is
     * yyyy[-mm[-dd[Thh:mm:ss(Z|(+|-)hh:mm)]]]
     *
     * @param n the element containing the date
     * @param id the VERS specification number (M number) for the element
     */
    boolean testDateValue(Node n, int id) {
        String s;
        NamedNodeMap attrs;
        int i;
        Node attr;

        // if element has an attribute, check that it is vers:scheme is ISO 8061
        attrs = n.getAttributes();
        if (attrs != null) {
            for (i = 0; i < attrs.getLength(); i++) {
                attr = attrs.item(i);
                if (attr.getNodeName().trim().equals("scheme")) {
                    s = attr.getNodeValue().trim().toLowerCase();
                    if (!equals(s, "iso 8061") && !equals(s, "iso8061")) {
                        startAttrError(n, id, attr, true);
                        Error("Attribute value should be 'ISO 8061.'");
                        confirmError();
                        return false;
                    }
                }
            }
        }

        // check value
        startValueError(n, id, true);
        s = getValue(n).trim();
        if (s.length() < 4) {
            dateFailed(n, 0, "Year must match 'yyyy'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(0)))
                || !(Character.isDigit(s.charAt(1)))
                || !(Character.isDigit(s.charAt(2)))
                || !(Character.isDigit(s.charAt(3)))) {
            dateFailed(n, 0, "Year must match 'yyyy'");
            return false;
        }
        if (s.length() == 4) {
            return true;
        }

        if (s.length() < 7) {
            dateFailed(n, 4, "Month must match '-MM'");
            return false;
        }
        if (s.charAt(4) != '-') {
            dateFailed(n, 4, "separator must be '-'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(5)))
                || !(Character.isDigit(s.charAt(6)))) {
            dateFailed(n, 5, "Month must be two digits");
            return false;
        }
        i = Character.digit(s.charAt(5), 10) * 10 + Character.digit(s.charAt(6), 10);
        if (i < 1 || i > 12) {
            dateFailed(n, 5, "month must be in the range '01' to '12'");
            return false;
        }

        if (s.length() == 7) {
            return true;
        }

        if (s.length() < 10) {
            dateFailed(n, 7, "Day must match '-dd'");
            return false;
        }
        if (s.charAt(7) != '-') {
            dateFailed(n, 7, "separator must be '-'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(8)))
                || !(Character.isDigit(s.charAt(9)))) {
            dateFailed(n, 8, "day must be two digits");
            return false;
        }
        i = Character.digit(s.charAt(8), 10) * 10 + Character.digit(s.charAt(9), 10);
        if (i < 1 || i > 31) {
            dateFailed(n, 8, "day must be in the range '01' to '31'");
            return false;
        }

        if (s.length() == 10) {
            return true;
        }

        if (s.length() < 20) {
            dateFailed(n, 10, "Times must match 'Thh:mm:ssZ[xx:yy]'");
            return false;
        }

        if (s.charAt(10) != 'T') {
            dateFailed(n, 10, "separator must be 'T'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(11)))
                || !(Character.isDigit(s.charAt(12)))) {
            dateFailed(n, 11, "hour must be two digits");
            return false;
        }
        if (Character.digit(s.charAt(11), 10) * 10 + Character.digit(s.charAt(12), 10) > 23) {
            dateFailed(n, 11, "hour must be in the range '00' to '23'");
            return false;
        }

        if (s.charAt(13) != ':') {
            dateFailed(n, 13, "separator must be ':'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(14)))
                || !(Character.isDigit(s.charAt(15)))) {
            dateFailed(n, 14, "minutes must be two digits");
            return false;
        }
        if (Character.digit(s.charAt(14), 10) * 10 + Character.digit(s.charAt(15), 10) > 59) {
            dateFailed(n, 14, "minutes must be in the range '00' to '59'");
            return false;
        }

        if (s.charAt(16) != ':') {
            dateFailed(n, 16, "separator must be ':'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(17)))
                || !(Character.isDigit(s.charAt(18)))) {
            dateFailed(n, 17, "seconds must be two digits");
            return false;
        }
        if (Character.digit(s.charAt(17), 10) * 10 + Character.digit(s.charAt(18), 10) > 59) {
            dateFailed(n, 17, "seconds must be in the range '00' to '59'");
            return false;
        }

        if ((s.charAt(19) == 'Z' || s.charAt(19) == 'z') && s.length() == 20) {
            return true;
        }

        if (!(s.charAt(19) == '+' || s.charAt(19) == '-')) {

            dateFailed(n, 19, "Timezone must be 'Z' or '+hh:mm' or '-hh:mm'");
            return false;
        }

        if (s.length() < 25) {
            dateFailed(n, 20, "Timezones must match 'mm:ss'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(20)))
                || !(Character.isDigit(s.charAt(21)))) {
            dateFailed(n, 20, "minutes must be two digits");
            return false;
        }
        if (Character.digit(s.charAt(20), 10) * 10 + Character.digit(s.charAt(21), 10) > 14) {
            dateFailed(n, 20, "hours must be in the range '00' to '14'");
            return false;
        }

        if (s.charAt(22) != ':') {
            dateFailed(n, 22, "separator must be ':'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(23)))
                || !(Character.isDigit(s.charAt(24)))) {
            dateFailed(n, 23, "minutes must be two digits");
            return false;
        }
        if (Character.digit(s.charAt(23), 10) * 10 + Character.digit(s.charAt(24), 10) > 59) {
            dateFailed(n, 23, "minutes must be in the range '00' to '59'");
            return false;
        }
        return true;
    }

    /**
     * Generic date message
     */
    void dateFailed(Node n, int posn, String err) {
        String s;
        int i;

        s = n.getNodeName();
        Error("      ");
        for (i = 0; i < s.length() + posn + 37; i++) {
            Error("-");
        }
        Error("^ ");
        Error(err);
        confirmError();
    }

    /**
     * Start a tentative error message about an element problem
     *
     * This involves printing out the element name
     *
     * @param n	element
     * @param id	VERS id of element we are testing
     */
    void startElementError(Node n, int id) {
        startError(1, "Error in element <" + n.getNodeName() + "> (M" + id + ")");
    }

    /**
     * Start a tentative error message about an attribute problem
     *
     * This involves printing out the element name and the value of the
     * attribute
     *
     * @param element element containing attribute
     * @param id	VERS id of element we are testing
     * @param attr	attribute
     * @param printValue print the attribute value if true
     */
    void startAttrError(Node element, int id, Node attr, boolean printValue) {
        StringBuffer sb;

        sb = new StringBuffer();
        sb.append("Error in attribute ");
        sb.append(attr.getNodeName() + " ");
        if (printValue) {
            sb.append("(value='" + attr.getNodeValue() + "') ");
        }
        sb.append("in element <" + element.getNodeName() + "> (M" + id + ")");
        startError(2, sb.toString());
    }

    /**
     * Start a tentative error message about a value problem
     *
     * This involves printing out the element name and value
     *
     * @param element element
     * @param id	VERS id of element we are testing
     * @param printValue print the value if true
     */
    void startValueError(Node n, int id, boolean printValue) {
        String s;
        StringBuffer sb;

        sb = new StringBuffer();
        sb.append("Error in value of element <" + n.getNodeName() + "> (M" + id + ").");
        if (printValue) {
            sb.append(" Value is ");
            s = getValue(n);
            if (s.equals("") || s.equals(" ")) {
                sb.append("<empty>");
            } else {
                sb.append("'" + s + "'");
            }
        }
        startError(3, sb.toString());
    }

    /**
     * Start a tentative error message about a missing element that is mandatory
     * in version 2
     */
    void startV2MissingError() {
        startError(4, "Element that is mandatory in a version 2 VEO is missing");
    }

    /**
     * Start a tentative error message about a missing element that is mandatory
     * in version 1
     */
    void startV1MissingError() {
        startError(5, "Element that is mandatory in a version 1 VEO is missing");
    }

    /**
     * Start a tentative error message about a mandatory missing element
     */
    void startMissingError() {
        startError(6, "Missing mandatory element");
    }

    /**
     * Start a tentative error message about a V2 feature in a V1 VEO
     */
    void startV2inV1Error() {
        startError(7, "Version 2 feature in a version 1 VEO");
    }

    /**
     * Start a tentative error message about a V1 feature in a V2 VEO
     */
    void startV1inV2Error() {
        startError(8, "Version 1 feature in a version 2 VEO");
    }

    /**
     * Start a tentative error message about a missing mandatory attribute in a
     * V2 VEO
     */
    void startMissingAttrError() {
        startError(9, "Missing mandatory attribute in a version 2 VEO");
    }

    /**
     * Start an error message for a check value
     */
    void startError(int id, String s) {
        errorMsg.setLength(0);
        errorMsg.append("VAL" + id + ": " + s);
        errorMsg.append("\r\n");
    }

    /**
     * Continue an error message
     */
    void Error(String s) {
        errorMsg.append(s);
    }

    /**
     * We have decided the error actually did occur, so print it
     */
    void confirmError() {
        print(errorMsg.toString() + "\r\n");
    }
}
