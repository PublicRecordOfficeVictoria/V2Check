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
 *
 * <ul>
 * <li> 9.8.06 Fixed bugs: Did not check that a vers:DateTimeClosed was present
 * in a File VEO; required vers:AgencyIdentifier and vers:SeriesIdentifier to be
 * present in a naa:RelatedRecordId element
 * <li> 14.4.10 Fixed bugs: When testing naa:SchemeType and checking for
 * vers:Subject or vers:Function only went up to the parent node (vers:Title)
 * not the grandparent (vers:RecordMetadata)
 * <li> 11.5.10 Fixed bug: When checking naa:SecurityClassification, only
 * checked the first four assigned values.
 * <li> 27.10.14 Added checking for additional formats in new VERS standard.
 * <li>20150518 Imported into NetBeans.
 * </ul> ************************************************************
 */
import VERSCommon.LTSF;
import VERSCommon.ResultSummary;
import VERSCommon.ResultSummary.Type;
import VERSCommon.VEOFailure;
import java.io.Writer;
import java.util.HashMap;
import java.util.logging.Level;
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
    String originalVEOType;	// original type of VEO according to the vers:originalVEOType attribute
    boolean inRevisedVEO;	// true if in a vers:RevisedVEO element
    boolean inOriginalVEO;	// true if in a vers:OriginalVEO element
    String schemeType;          // type of title scheme
    String currentContext;	// current context of VEO
    HashMap<String, Node> nodeLabels; // hash table of vers:id
    LTSF ltsfs;                 // list of valid formats
    boolean vpa;                // true if being run from VPA - if so, don't test for LTSF or Security Classification present
    boolean migration;          // true if migrating from old DSA - back off on some of the validation

    // Logging
    private final static Logger LOG = Logger.getLogger("VEOCheck.TestValues");

    /**
     * Constructor
     *
     * @param verbose
     * @param strict
     * @param vpa true if being run from VPA (don't test LTSF or Security Class)
     * @param oneLayer
     * @param ltsfs
     * @param migration true if migrating from old DSA - back off on some of the
     * validation
     * @param out
     * @param results
     */
    public TestValues(boolean verbose, boolean strict, boolean vpa, boolean oneLayer, LTSF ltsfs, boolean migration, Writer out, ResultSummary results) {
        super(verbose, strict, oneLayer, out, results);
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
        this.ltsfs = ltsfs;
        this.vpa = vpa;
        this.migration = migration;
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
     * This class tests the metadata in a VEO.It prints out the metadata in a
     * flat format (to aid checking) and checks that there are no empty
     * elements.
     *
     * @param filename
     * @param veo the VEO to check
     * @return true if parse succeeded
     */
    public boolean performTest(String filename, Element veo) {
        String s;

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
        this.veoName = filename;
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
            failed("TestValues", "performTest", 1, "The VEO contained the following empty elements:");
        }

        // check values for validity against specification
        startSubTest("INVALID VALUES");
        labelNodes(veo);
        if (checkInvalidValues(null, veo, 1)) {
            passed("The VEO contained no invalid elements");
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
     * exist, and the test will fail if any are found. Returns true if all
     * elements have content
     */
    private boolean checkForEmptyElements(Node n, int indent) {
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

        // if in migration mode, ignore some of the elements...
        if (migration) {
            if (n.getNodeName().equals("naa:Description")) {
                return true;
            }
        }

        // do not check inside onion VEO or originalVEO if oneLayer is set
        if (oneLayer) {
            if (((n.getNodeName().equals("vers:DocumentData"))
                    && testElementExists(n, "vers:VERSEncapsulatedObject"))
                    || n.getNodeName().equals("vers:OriginalVEO")) {
                return true;
            }
        }

        // print element out if it is empty
        passed = !elementIsEmpty(n);
        if (!passed) {
            capture("  <" + n.getNodeName() + ">");
        }

        // otherwise check each child
        child = n.getFirstChild();
        while (child != null) {
            passed &= checkForEmptyElements(child, indent + 1);
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

        switch (n.getNodeName()) {
            case "vers:VERSEncapsulatedObject":
                return testVERSEncapsulatedObject(n);
            case "vers:Version":
                return testVersion(n);
            case "vers:SignatureBlock":
                return testSignatureBlock(n);
            case "vers:LockSignatureBlock":
                return testLockSignatureBlock(n);
            case "vers:SignatureAlgorithmIdentifier":
                return testSignatureAlgorithmIdentifier(n);
            case "vers:SignatureDate":
                return testDateValue(n, 136);
            case "vers:SignedObject":
                return testSignedObject(n);
            case "vers:ObjectType":
                return testObjectType(n);
            case "vers:ObjectContent":
                return testObjectContent(n);
            case "vers:ObjectCreationDate":
                return testDateValue(n, 8);
            case "vers:ModifiedVEO":
                return testModifiedVEO(n);
            case "vers:RevisedVEO":
                return testRevisedVEO(n);
            case "vers:OriginalVEO":
                return testOriginalVEO(n);
            case "vers:RecordMetadata":
                return testRecordMetadata(n);
            case "naa:SecurityClassification":
                return testSecurityClassification(n);
            case "naa:AccessStatus":
                return testAccessStatus(n);
            case "naa:SchemeType":
                return testSchemeType(n);
            case "vers:Subject":
                return testSubject(n);
            case "vers:AuxiliaryDescription":
                return testAuxiliaryDescription(n);
            case "naa:RelatedItemId":
                return testRelatedItemId(n);
            case "vers:Date":
                return testVERSDate(n);
            case "naa:DateTimeCreated":
                return testDateValue(n, 55);
            case "naa:DateTimeTransacted":
                return testDateValue(n, 56);
            case "naa:DateTimeRegistered":
                return testDateValue(n, 57);
            case "vers:DateTimeClosed":
                return testDateValue(n, 144);
            case "naa:AggregationLevel":
                return testAggregationLevel(n);
            case "naa:EventDateTime":
                return testDateValue(n, 68);
            case "naa:UseDateTime":
                return testDateValue(n, 73);
            case "naa:UseType":
                return testUseType(n);
            case "naa:ActionDateTime":
                return testDateValue(n, 78);
            case "naa:NextActionDue":
                return testDateValue(n, 82);
            case "naa:DisposalStatus":
                return testDisposalStatus(n);
            case "naa:RefersTo":
                return testRefersTo(n);
            case "vers:VEOIdentifier":
                return testVEOIdentifier(parent, n);
            case "vers:AgencyIdentifier":
                return testAgencyIdentifier(n);
            case "vers:SeriesIdentifier":
                return testSeriesIdentifier(n);
            case "naa:DisposalActionDue":
                startValueError("checkElement", 1, n, 3, true);
                continueError("Value must be one of: ");
                if (checkValue(n, "Null", " ")) {
                    return true;
                }
                return testDateValue(n, 91);
            case "vers:OriginatorsCopy":
                return testOriginatorsCopy(n);
            case "vers:Document":
                return testDocument(n);
            case "vers:DocumentRightsManagement":
                return testDocumentRightsManagement(n);
            // Document Language to do
            case "vers:DocumentDate":
                return testDateValue(n, 123);
            case "vers:DocumentFunction":
                return testDocumentFunction(n);
            case "vers:Encoding":
                return testEncoding(n);
            case "vers:EncodingMetadata":
                return testEncodingMetadata(n);
            case "vers:FileRendering":
                return testFileRendering(n);
            case "vers:RenderingKeywords":
                return testRenderingKeywords(n);
            case "vers:DocumentData":
                return testDocumentData(n);
            case "vers:DateTimeModified":
                return testDateValue(n, 157);
            case "vers:DisposalDate":
                return testDateValue(n, 147);
            default:
        }
        return true;
    }

    /**
     * Test a vers:VERSEncapsulatedObject (10)
     */
    private boolean testVERSEncapsulatedObject(Node n) {
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
            if (n1 == null) { // this should never occur as it would be a DTD violation
                startMissingError("testVERSEncapsulatedObject", 1);
                continueError("A vers:VERSEncapsulatedObject (M1) element must contain a vers:Version (M3) element");
                confirmError();
                thisLayerVersion = "Unknown";
                passed = false;
            } else {
                thisLayerVersion = getValue(n1);
            }
        }
        thisLayerType = null;	// don't know yet...

        // test for correct namespace
        if (layer == 1 && !testAttribute("testVERSEncapsulatedObject", 2, n, 1, "xmlns:vers", versNamespace)) {
            passed = false;
        }
        if (layer == 1 && !testAttribute("testVERSEncapsulatedObject", 3, n, 1, "xmlns:naa", naaNamespace)) {
            passed = false;
        }

        // if v2, check for signature block and at least one lock
        // signature block
        if (thisLayerVersion.equals("2.0")) {
            if (!testElementExists(n, "vers:SignatureBlock")) {
                startV2MissingError("testVERSEncapsulatedObject", 4);
                continueError("A version 2.0 VEO must contain at least one <vers:SignatureBlock> (M134) element");
                confirmError();
                passed = false;
            }
            if (!testElementExists(n, "vers:LockSignatureBlock")) {
                startV2MissingError("testVERSEncapsulatedObject", 5);
                continueError("A version 2.0 VEO must contain at least one <vers:LockSignatureBlock> (M152) element");
                confirmError();
                passed = false;
            }
        }
        return passed;
    }

    /**
     * Test a vers:Version (20)
     */
    private boolean testVersion(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError("testVersion", 1, n, 3, true);
        continueError("Value must be one of: ");
        if (!checkValue(n, "1.2", " or ") && !checkValue(n, "2.0", " ")) {
            confirmError();
            passed = false;
        }

        // if tester is forcing version of outer layer, over-ride
        // version in vers:Version
        if (forceVersion != null && layer == 1) {
            thisLayerVersion = forceVersion;
            startValueError("testVersion", 2, n, 3, true);
            continueError("Value must be ");
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
     * Test a vers:SignatureBlock (30)
     */
    private boolean testSignatureBlock(Node n) {
        boolean passed = true;

        // error if version 1 and vers:id attribute present
        if (thisLayerVersion.equals("1.2") && findAttribute(n, "vers:id") != null) {
            startV2inV1Error("testSignatureBlock", 1);
            continueError("A version 1 <vers:SignatureBlock> (M134) element cannot contain a vers:id attribute");
            confirmError();
            passed = false;
        }

        // error if version 2 and vers:VEOVersion attribute not present
        if (thisLayerVersion.equals("2.0")) {
            passed = checkVersId("testSignatureBlock", 2, n, 134);
        }
        return passed;
    }

    /**
     * Test a vers:LockSignatureBlock (40)
     */
    private boolean testLockSignatureBlock(Node n) {
        boolean passed = true;
        String id;
        Node attr, n1;
        String s[];

        // error if version 1 and lock signature block present
        if (thisLayerVersion.equals("1.2")) {
            startV2inV1Error("testLockSignatureBlock", 1);
            continueError("A version 1 VEO cannot contain a <vers:LockSignatureBlock> (M152) element");
            confirmError();
            passed = false;
        }

        // get vers:signsSignatureBlock attribute node
        attr = findAttribute(n, "vers:signsSignatureBlock");
        if (attr == null) {
            startMissingAttrError("testLockSignatureBlock", 2);
            continueError("A <vers:LockSignatureBlock> (M152) element must contain a vers:signsSignatureBlock attribute");
            confirmError();
            return false;
        }

        // check vers:signsSignatureBlock for conformance to pattern
        id = attr.getNodeValue();
        s = id.split("-");
        if (s.length != 4
                || !equals(s[0], "Revision") || !testVersIdNumber(s[1])
                || !equals(s[2], "Signature") || !testVersIdNumber(s[3])) {
            startAttrError("testLockSignatureBlock", 3, n, 152, attr, true);
            continueError("Attribute value must match the pattern 'Revision-<int>-Signature-<int>'");
            confirmError();
            passed = false;
        }

        // check that vers:signsSignatureBlock points to a vers:SignatureBlock
        n1 = (Node) nodeLabels.get(id);
        if (n1 == null
                || n1.getNodeType() != Node.ELEMENT_NODE
                || !n1.getNodeName().equals("vers:SignatureBlock")) {
            startAttrError("testLockSignatureBlock", 4, n, 152, attr, true);
            continueError("Attribute value does not point to a <vers:SignatureBlock> (M134) element");
            confirmError();
            passed = false;
        }

        return passed;
    }

    /**
     * Test a vers:SignatureAlgorithmIdentifier (50)
     */
    private boolean testSignatureAlgorithmIdentifier(Node n) {
        boolean passed = true;

        // test for controlled values
        /* This test is not necessary, as the algorithm identifiers are tested when validating the signature
        startValueError("testSignatureAlgorithmIdentifier", 1, n, 150, true);
        continueError("Value must be one of: ");
        if (!checkValue(n, "1.2.840.113549.1.1.5", ", ")
                && !checkValue(n, "1.2.840.113549.1.1.11", ", ")
                && !checkValue(n, "1.2.840.113549.1.1.13", " or ")
                && !checkValue(n, "1.2.840.10040.4.3", " ")) {
            confirmError();
            passed = false;
        }
         */
        return passed;
    }

    /**
     * Test a vers:SignedObject (60)
     */
    private boolean testSignedObject(Node n) {
        boolean passed = true;
        Node a;
        String s1;

        // error if version 1 and vers:VEOVersion attribute present
        if (thisLayerVersion.equals("1.2") && findAttribute(n, "vers:VEOVersion") != null) {
            startV2inV1Error("testSignedObject", 1);
            continueError("A version 1 <vers:SignedObject> (M4) element cannot contain a vers:VEOVersion attribute");
            confirmError();
            passed = false;
        }

        // error if version 2 and vers:VEOVersion attribute not present
        // or not '2.0'
        if (thisLayerVersion.equals("2.0")) {
            a = findAttribute(n, "vers:VEOVersion");
            if (a == null) {
                startElementError("testSignedObject", 2, n, 4);
                continueError("A version 2.0 <vers:SignedObject> (M4) must contain a vers:VEOVersion attribute");
                confirmError();
                return false;
            }

            s1 = a.getNodeValue().trim();
            if (!s1.equals("2.0")) {
                startAttrError("testSignedObject", 3, n, 4, a, true);
                continueError("which must be '2.0' to match <vers:Version> (M3) element");
                confirmError();
                passed = false;
            }
        }
        return passed;
    }

    /**
     * Test a vers:ObjectType (70)
     */
    private boolean testObjectType(Node n) {
        boolean passed = true;

        thisLayerType = getValue(n);

        // test for controlled values
        if (thisLayerVersion.equals("1.2")) {
            startValueError("testObjectType", 1, n, 6, true);
            continueError("Value must be one of: ");
            if (!checkValue(n, "File", " or ") && !checkValue(n, "Record", " ")) {
                continueError("in a version 1 VEO");
                confirmError();
                passed = false;
            }
        }
        if (thisLayerVersion.equals("2.0")) {
            startValueError("testObjectType", 2, n, 6, true);
            continueError("Value must be one of: ");
            if (!checkValue(n, "File", ", ")
                    && !checkValue(n, "Record", " or ")
                    && !checkValue(n, "Modified VEO", " ")) {
                continueError("in a version 2 VEO");
                confirmError();
                passed = false;
            }
            if (inRevisedVEO && !equals(originalVEOType, getValue(n))) {
                startValueError("testObjectType", 3, n, 6, true);
                continueError("The value of the <vers:ObjectType> (M6) element in a <vers:RevisedVEO> (M158) element must match the value of the vers:OriginalVEOType attribute in the <vers:ModifiedVEO> (M156) element (which was " + originalVEOType + ")");
                confirmError();
                inRevisedVEO = false;
                passed = false;
            }
            if (inOriginalVEO
                    && !(equals(originalVEOType, getValue(n))
                    || equals("Modified VEO", getValue(n)))) {
                startValueError("testObjectType", 4, n, 6, true);
                continueError("The value of the <vers:ObjectType> (M6) element in a <vers:OriginalVEO> (M159) element must match the value of the vers:OriginalVEOType attribute in the <vers:ModifiedVEO> (M156) element (which was " + originalVEOType + ") or be 'Modified VEO'");
                confirmError();
                inOriginalVEO = false;
                passed = false;
            }
        }
        return passed;
    }

    /**
     * Test a vers:ObjectContent (80)
     */
    private boolean testObjectContent(Node n) {
        boolean passed = true;

        if (equals(thisLayerType, "File") && !testElementExists(n, "vers:File")) {
            startError("testObjectContent", 1, "Error in value of element <vers:ObjectContent> (M9)");
            continueError("The value of the <vers:ObjectType> (M6) element is 'File' but the <vers:ObjectContent> (M9) element does not contain a <vers:File> (M142) element");
            confirmError();
            passed = false;
        }
        if (equals(thisLayerType, "Record") && !testElementExists(n, "vers:Record")) {
            startError("testObjectContent", 2, "Error in value of element <vers:ObjectContent> (M9)");
            continueError("The value of the <vers:ObjectType> (M6) element is 'Record' but the <vers:ObjectContent> (M9) element does not contain a <vers:Record> (M10) element");
            confirmError();
            passed = false;
        }
        if (equals(thisLayerType, "Modified VEO") && !testElementExists(n, "vers:ModifiedVEO")) {
            startError("testObjectContent", 3, "Error in value of element <vers:ObjectContent> (M9)");
            continueError("The value of the <vers:ObjectType> (M6) element is 'Modified VEO' but the <vers:ObjectContent> (M9) element does not contain a <vers:ModifiedVEO> (M156) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a vers:ModifiedVEO (90)
     */
    private boolean testModifiedVEO(Node n) {
        boolean passed = true;
        String s;
        Node attr;

        // remember value of vers:OriginalVEOType
        s = originalVEOType;
        attr = findAttribute(n, "vers:OriginalVEOType");
        if (attr == null) {
            startMissingAttrError("testModifiedVEO", 1);
            continueError("A <vers:ModifiedVEO> (M156) element must contain a vers:OriginalVEOType attribute");
            confirmError();
            originalVEOType = "Unknown";
            passed = false;
        } else {
            originalVEOType = attr.getNodeValue();
        }

        // check for valid values of vers:OriginalVEOType attribute
        if (!equals(originalVEOType, "File") && !equals(originalVEOType, "Record")) {
            startAttrError("testModifiedVEO", 2, n, 156, attr, true);
            continueError("The value of the vers:OriginalVEOType attribute within a <vers:ModifiedVEO> (M156) element must be either 'File' or 'Record'");
            confirmError();
            passed = false;
        }

        // second and later vers:ModifiedVEO elements must have the same
        // value as the first
        if (s != null && !equals(originalVEOType, s)) {
            startAttrError("testModifiedVEO", 3, n, 156, attr, true);
            continueError("An inner <vers:ModifiedVEO> (M156) element has a vers:OriginalVEOType attribute with the value (" + s + ") that does not match the type of the outermost <vers:ModifiedVEO> (M156) element (which was '" + originalVEOType + "')");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a vers:RevisedVEO (100)
     */
    private boolean testRevisedVEO(Node n) {
        boolean passed = true;

        inRevisedVEO = true;
        inOriginalVEO = false;
        if (findAttribute(n, "vers:id") == null) {
            startMissingAttrError("testRevisedVEO", 1);
            continueError("A <vers:RevisedVEO> (M158) element must contain a vers:id attribute");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a vers:OriginalVEO (110)
     */
    private boolean testOriginalVEO(Node n) {
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
            startV2MissingError("testOriginalVEO", 1);
            continueError("A <vers:OriginalVEO> (M159) element must contain a <vers:Version> (M3) element");
            confirmError();
            thisLayerVersion = "Unknown";
            passed = false;
        } else {
            thisLayerVersion = getValue(n1);
        }
        return passed;
    }

    /**
     * Test a vers:RecordMetadata (120)
     */
    private boolean testRecordMetadata(Node n) {
        boolean passed = true;
        if (thisLayerVersion.equals("1.2") && !testElementExists(n, "naa:RecordIdentifier")) {
            startV1MissingError("testRecordMetadata", 1);
            continueError("In a version 1 VEO, a <vers:RecordMetadata> (M11) element must contain a <naa:RecordIdentifier> (M65) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a vers:SecurityClassification (130) 20191209 - Added the
     * classifications Unofficial to Personal Privacy 20200205 - Forced a
     * relaxed test of equality a/c transfer request 20220408 - Added 'Not
     * Reviewed' a/c transfer request and further relaxed value comparison
     * 20230227 - do not carry out this test if being called from the VPA
     */
    private boolean testSecurityClassification(Node n) {
        boolean passed = true;

        // test for controlled values
        if (!vpa) {
            startValueError("testSecurityClassification", 1, n, 25, true);
            continueError("which must be: ");
            if (!checkValueRelaxed(n, "Unclassified", ", ")
                    && !checkValueRelaxed(n, "Not Reviewed", ", ")
                    && !checkValueRelaxed(n, "In-Confidence", ", ")
                    && !checkValueRelaxed(n, "Protected", ", ")
                    && !checkValueRelaxed(n, "Highly Protected", ", ")
                    && !checkValueRelaxed(n, "Restricted", ", ")
                    && !checkValueRelaxed(n, "Confidential", ", ")
                    && !checkValueRelaxed(n, "Secret", ", ")
                    && !checkValueRelaxed(n, "Top Secret", ", ")
                    && !checkValueRelaxed(n, "Unofficial", ", ")
                    && !checkValueRelaxed(n, "OFFICIAL", ", ")
                    && !checkValueRelaxed(n, "OFFICIAL:Sensitive", ", ")
                    && !checkValueRelaxed(n, "Cabinet-in-Confidence", ", ")
                    && !checkValueRelaxed(n, "Legal Privilege", ", ")
                    && !checkValueRelaxed(n, "Legislative Secrecy", ", or ")
                    && !checkValueRelaxed(n, "Personal Privacy", " ")) {
                confirmError();
                passed = false;
            }
        }
        return passed;
    }

    /**
     * Test a naa:AccessStatus (140)
     */
    private boolean testAccessStatus(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError("testAccessStatus", 1, n, 29, true);
        continueError("Value must be one of: ");
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
     * Test a naa:SchemeType (150)
     */
    private boolean testSchemeType(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError("testSchemeType", 1, n, 33, true);
        continueError("Value must be one of: ");
        if (!checkValue(n, "Functional", ", ")
                && !checkValue(n, "Subject-based", " or ")
                && !checkValue(n, "Free Text", " ")) {
            confirmError();
            passed = false;
        }

        // Check that VEO has appropriate titling mechanism
        if (equals(getValue(n), "Subject-based")
                && !testElementExists(n.getParentNode().getParentNode(), "vers:Subject")) {
            startValueError("testSchemeType", 2, n, 33, false);
            continueError("has the value 'Subject-based', but VEO does not contain a <vers:Subject> (M37) element");
            confirmError();
            passed = false;
        }
        if (equals(getValue(n), "Functional")
                && !testElementExists(n.getParentNode().getParentNode(), "naa:Function")) {
            startValueError("testSchemeType", 3, n, 33, false);
            continueError("has the value 'Functional', but VEO does not contain a <naa:Function> (M50) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a vers:Subject (160)
     */
    private boolean testSubject(Node n) {
        boolean passed = true;

        /* this test will never fail as a missing keyword is a parse error
        if (!testElementExists(n, "vers:Keyword")) {
            startElementError("testSubject", 1, n, 37);
            continueError("A <vers:Subject> (M37) element must contain at least one <vers:Keyword> (M39) element");
            confirmError();
            passed = false;
        }
         */
        return passed;
    }

    /**
     * Test a vers:AuxiliaryDescription (170)
     */
    private boolean testAuxiliaryDescription(Node n) {
        boolean passed = true;

        // error if present in a version 1 VEO
        if (thisLayerVersion.equals("1.2")) {
            startV2inV1Error("testAuxiliaryDescription", 1);
            continueError("A version 1 VEO cannot contain a <vers:AuxiliaryDescription> (M153) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a naa:RelatedItemId (180)
     */
    private boolean testRelatedItemId(Node n) {
        boolean passed = true;

        if (thisLayerVersion.equals("2.0") && !testElementExists(n, "vers:VEOIdentifier")) {
            startV2MissingError("testRelatedItemId", 1);
            continueError("In version 2.0, a <vers:RelatedItemId> (M43) element must contain a <vers:VEOIdentifier> (M99) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a vers:Date (185)
     *
     * ajw 9/8/06. Method added to ensure that vers:DateTimeClosed is present in
     * a file VEO.
     */
    private boolean testVERSDate(Node n) {
        boolean passed = true;

        if (!testElementExists(n, "vers:DateTimeClosed")) {
            startV2MissingError("testVERSDate", 1);
            continueError("In a File VEO, a <vers:Date> (M54) element must contain a <vers:DateTimeClosed> (M144) element when submitted to PROV");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a naa:AggregationLevel (190)
     */
    private boolean testAggregationLevel(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError("testAggregationLevel", 1, n, 59, true);
        continueError("Value must be one of: ");
        if (!checkValue(n, "File", " or ") && !checkValue(n, "Item", " ")) {
            confirmError();
            passed = false;
        } else {
            if (equals(thisLayerType, "File") && !equals(getValue(n), "File")) {
                startValueError("testAggregationLevel", 2, n, 59, true);
                continueError("The value of the <naa:AggregationLevel> (M159) element (which is " + getValue(n) + ") must be 'File' to match the content of the enclosing <vers:ObjectType> (M6) element");
                confirmError();
                passed = false;
            }
            if (equals(thisLayerType, "Record") && !equals(getValue(n), "Item")) {
                startValueError("testAggregationLevel", 3, n, 59, true);
                continueError("The value of the <naa:AggregationLevel> (M159) element (which is " + getValue(n) + ") must be 'Item' as the value of the <vers:ObjectType> (M6) element is 'Record'");
                confirmError();
                passed = false;
            }
        }
        return passed;
    }

    /**
     * Test a naa:UseType (200)
     */
    private boolean testUseType(Node n) {
        boolean passed = true;

        // test for controlled values
        if (!strict) {
            return true;
        }
        startValueError("testUseType", 1, n, 74, true);
        continueError("Value must be one of: ");
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
     * Test a naa:DisposalStatus (210)
     */
    private boolean testDisposalStatus(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError("testDisposalStatus", 1, n, 92, true);
        continueError("Value must be one of: ");
        if (!checkValue(n, "Permanent", ", ")
                && !checkValue(n, "Temporary", " or ")
                && !checkValue(n, "Unknown", " ")) {
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a naa:RefersTo (220)
     */
    private boolean testRefersTo(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError("testRefersTo", 1, n, 95, true);
        continueError("Value must be one of: ");
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
     * Test a vers:VEOIdentifier (230)
     *
     * ajw 9/8/06 doesn't test for vers:AgencyIdentifier and
     * vers:SeriesIdentifier if in a naa:RelatedItemId. Required adding context
     * (parent) node.
     */
    private boolean testVEOIdentifier(Node parent, Node n) {
        boolean passed = true;
        if (!parent.getNodeName().equals("naa:RelatedItemId")
                && !testElementExists(n, "vers:AgencyIdentifier")) {
            startMissingError("testVEOIdentifier", 1);
            continueError("A <vers:VEOIdentifier> (M99) element must contain a <vers:AgencyIdentifier> (M100) element when submitted to PROV");
            confirmError();
            passed = false;
        }
        if (!parent.getNodeName().equals("naa:RelatedItemId")
                && !testElementExists(n, "vers:SeriesIdentifier")) {
            startMissingError("testVEOIdentifier", 2);
            continueError("A <vers:VEOIdentifier> (M99) element must contain a <vers:SeriesIdentifier> (M101) element when submitted to PROV");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a vers:AgencyIdentifier (240)
     */
    private boolean testAgencyIdentifier(Node n) {
        boolean passed = true;
        String s;

        s = getValue(n).trim();
        try {
            Integer.parseInt(s);
        } catch (NumberFormatException nfe) {
            startValueError("testAgencyIdentifier", 1, n, 100, true);
            continueError("Value must be the VA number (without leading 'VA')");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a vers:SeriesIdentifier (250)
     */
    private boolean testSeriesIdentifier(Node n) {
        boolean passed = true;
        String s;

        s = getValue(n).trim();
        try {
            Integer.parseInt(s);
        } catch (NumberFormatException nfe) {
            startValueError("testSeriesIdentifier", 1, n, 101, true);
            continueError("Value must be the VPRS number (without leading 'VPRS')");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a vers:OriginatorsCopy (260)
     */
    private boolean testOriginatorsCopy(Node n) {
        boolean passed = true;

        // test for controlled values
        startValueError("testOriginatorsCopy", 1, n, 109, true);
        continueError("Value must be one of: ");
        if (!checkValue(n, "true", " or ")
                && !checkValue(n, "false", " ")) {
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * Test a vers:Document (270) The source for the MIME types is the official
     * IANA list
     * http://www.iana.org/assignments/media-types/media-types.xhtml#text, which
     * has been checked against the Library of Congress files type information
     * http://www.digitalpreservation.gov/formats
     */
    private boolean testDocument(Node n) {
        boolean passed = true;
        String s, ids[];
        Node attr, n1;
        boolean foundSubDocAttr;
        int i;
        NodeList nl;
        boolean foundLtpf;
        StringBuffer fmtsFound;

        // test to see if Document contains a valid long term preservation
        // format encoding (only if not being called from VPA)
        if (!vpa) {
            nl = ((Element) n).getElementsByTagName("vers:RenderingKeywords");
            foundLtpf = false;
            fmtsFound = new StringBuffer();
            for (i = 0; i < nl.getLength() && !foundLtpf; i++) {
                n1 = (Element) nl.item(i);
                s = getValue(n1).trim().toLowerCase();
                fmtsFound.append(s);
                if (ltsfs.isV2LTSF(s)) {
                    foundLtpf = true;
                }
            }
            if (!foundLtpf) {
                startError("testDocument", 1, "Document without Long Term Preservation Format");
                continueError("A <Document> (M114) element must contain an <Encoding> (M126) element with a valid long term preservation format for acceptance into the digital archive. ");
                if (nl.getLength() == 0) {
                    continueError("The Document has no <vers:RenderingKeywords> (M132) elements and so no long term preservation formats can be identified");
                } else {
                    continueError("Formats found in this Document are: " + fmtsFound.toString());
                }
                confirmError();
                passed = false;
            }
        }

        // test for attributes in V1 VEOs
        if (thisLayerVersion.equals("1.2")) {
            if (findAttribute(n, "vers:id") != null) {
                startV2inV1Error("testDocument", 2);
                continueError("In a version 1 VEO, a <vers:Document> (M114) element cannot contain a vers:id attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:subordinateDocuments") != null) {
                startV2inV1Error("testDocument", 3);
                continueError("In a version 1 VEO, a <vers:Document> (M114) element cannot contain a vers:subordinateDocuments attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:subordinateDocumentRelationship") != null) {
                startV2inV1Error("testDocument", 4);
                continueError("In a version 1 VEO, a <vers:Document> (M114) element cannot contain a vers:subordinateDocumentRelationship attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:parentDocument") != null) {
                startV2inV1Error("testDocument", 5);
                continueError("In a version 1 VEO, a <vers:Document> (M114) element cannot contain a vers:parentDocument attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:presentThisDocument") != null) {
                startV2inV1Error("testDocument", 6);
                continueError("In a version 1 VEO, a <vers:Document> (M114) element cannot contain a vers:presentThisDocument attribute");
                confirmError();
                passed = false;
            }
            if (!testElementExists(n, "vers:Encoding")) {
                startV1MissingError("testDocument", 7);
                continueError("In a version 1 VEO, a <vers:Document> (M114) element must contain at least one <vers:Encoding> element");
                confirmError();
                passed = false;
            }
            return passed;
        }

        // the following tests are performed for version 2
        // check version id attribute
        if (!checkVersId("testDocument", 20, n, 114)) {
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
                    startAttrError("testDocument", 8, n, 114, attr, true);
                    continueError("The vers:subordinateDocuments attribute (value '" + ids[i] + "') does not point to a <vers:Document> (M114) element");
                    confirmError();
                    passed = false;
                }
                if (n == n1) {
                    startAttrError("testDocument", 9, n, 114, attr, true);
                    continueError("The vers:subordinateDocuments attribute (value '" + ids[i] + "') points to this <vers:Document> (M114) element");
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
                startAttrError("testDocument", 10, n, 114, attr, true);
                continueError("The vers:subordinateDocumentRelationship attribute must have the value 'Sequence', 'Set' or 'Alternative'");
                confirmError();
                passed = false;
            }
        }

        // test for valid vers:presentThisDocument
        attr = findAttribute(n, "vers:presentThisDocument");
        if (attr != null) {
            s = attr.getNodeValue();
            if (!s.equals("true") && !s.equals("false")) {
                startAttrError("testDocument", 11, n, 114, attr, true);
                continueError("The vers:presentThisDocument attribute must have the value 'true', or 'false'");
                confirmError();
                passed = false;
            }
        }

        if (!foundSubDocAttr && !testElementExists(n, "vers:Encoding")) {
            startV2MissingError("testDocument", 12);
            continueError("A version 2 <vers:Document> (M114) element must either contain <vers:Encoding> (M126) elements or a vers:subordinateDocuments attribute");
            passed = false;
        }

        return passed;
    }

    /**
     * TestSupport a vers:DocumentRightsManagement (280)
     */
    private boolean testDocumentRightsManagement(Node n) {
        boolean passed = true;

        // error if version 1 and document function present
        if (thisLayerVersion.equals("1.2")) {
            startV2inV1Error("testDocumentRightsManagement", 1);
            continueError("A version 1 VEO cannot contain a <vers:DocumentRightsManagement> (M154) element ");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:DocumentFunction (290)
     */
    private boolean testDocumentFunction(Node n) {
        boolean passed = true;

        // error if version 1 and document function present
        if (thisLayerVersion.equals("1.2")) {
            startV2inV1Error("testDocumentFunction", 1);
            continueError("A version 1 VEO cannot contain a <vers:DocumentFunction> (M155) element");
            confirmError();
            passed = false;
        }
        return passed;
    }

    /**
     * TestSupport a vers:Encoding (300)
     */
    private boolean testEncoding(Node n) {
        boolean passed = true;

        if (thisLayerVersion.equals("1.2") && findAttribute(n, "vers:id") != null) {
            startV2inV1Error("testEncoding", 1);
            continueError("A version 1 <vers:Encoding> (M126) element cannot contain a vers:id attribute");
            confirmError();
            passed = false;
        }
        if (thisLayerVersion.equals("2.0") && !checkVersId("testEncoding", 20, n, 126)) {
            passed = false;
        }
        return passed;
    }

    /**
     * Test a vers:EncodingMetadata (300)
     */
    private boolean testEncodingMetadata(Node n) {
        boolean passed = true;

        /* Test removed a/c request by Dave Fowler as it would clutter up the error logs
        if (!testElementExists(n, "vers:SourceFileIdentifier")) {
            startMissingError("testEncodingMetadata", 1);
            Error("A <vers:sourceFileIdentifier> (M129) element is expected by the ingest process to be present in each <vers:Encoding> (M126) element. The ingest process will use the value of the <vers:DocumentSource> (M125) if <vers:sourceFileIdentifier> is not present");
            confirmError();
            passed = false;
        }
         */
        return passed;
    }

    /**
     * Test a vers:FileRendering (310)
     */
    private boolean testFileRendering(Node n) {
        boolean passed = true;

        /* will never be true, as this will result in a parse error
        if (!testElementExists(n, "vers:RenderingKeywords")) {
            startMissingError("testFileRendering", 1);
            continueError("A <vers:RenderingKeywords> (M132) element must be present in each <vers:Encoding> (M126) element to allow automated extraction");
            confirmError();
            passed = false;
        }
        */
        return passed;
    }

    /**
     * Check the rendering keywords (320) This function breaks up the value into
     * the format keywords, then calls validFormat() to determine if the
     * keywords are valid. The syntax of the value is '<ft>[; <ft>]*' where ft
     * is .<ext>|<mime>
     */
    private boolean testRenderingKeywords(Node n) {
        String s;
        boolean passed = true;

        startValueError("testRenderingKeywords", 1, n, 132, true);
        s = getValue(n).trim();
        if (s == null || s.length() == 0) { //empty elements picked up elsewhere
            return false;
        }

        if (s.charAt(0) != '\'') {
            if (strict) {
                continueError("Value must start with quote (')");
                passed = false;
            }
        } else {
            s = s.substring(1, s.length());
        }
        if (s == null || s.length() == 0) {
            continueError(" (empty)");
            confirmError();
            return false;
        }
        if (s.charAt(s.length() - 1) != '\'') {
            if (strict) {
                continueError("Value must end with quote (')");
                passed = false;
            }
        } else {
            s = s.substring(0, s.length() - 1);
        }
        if (s == null || s.length() == 0) {
            continueError(" (empty)");
            passed = false;
        }
        if (!passed) {
            confirmError();
        }
        return passed;
    }

    /**
     * Test vers:DocumentData (330)
     */
    private boolean testDocumentData(Node n) {
        boolean passed = true;

        // test for attributes in V1
        if (thisLayerVersion.equals("1.2")) {
            if (findAttribute(n, "vers:id") != null) {
                startV2inV1Error("testDocumentData", 1);
                continueError("In a version 1 VEO, a <vers:DocumentData> (M133) element cannot contain a vers:id attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:forContentsSeeElement") != null) {
                startV2inV1Error("testDocumentData", 2);
                continueError("In a version 1 VEO, a <vers:DocumentData> (M133) element cannot contain a vers:forContentsSeeElement attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:forContentSeeElement") != null) {
                startV2inV1Error("testDocumentData", 3);
                continueError("In a version 1 VEO, a <vers:DocumentData> (M133) element cannot contain a vers:forContentSeeElement attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:forContentsSeeOriginalDocumentAndEncoding") != null) {
                startV2inV1Error("testDocumentData", 4);
                continueError("In a version 1 VEO, a <vers:DocumentData> (M133) element cannot contain a vers:forContentsSeeOriginalDocumentAndEncoding attribute");
                confirmError();
                passed = false;
            }
            if (findAttribute(n, "vers:forContentSeeOriginalDocumentAndEncoding") != null) {
                startV2inV1Error("testDocumentData", 5);
                continueError("In a version 1 VEO, a <vers:DocumentData> (M133) element cannot contain a vers:forContentSeeOriginalDocumentAndEncoding attribute");
                confirmError();
                passed = false;
            }
            return passed;
        }

        // check for valid version id...
        if (!checkVersId("testDocumentData", 20, n, 133)) {
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
     * Test a link from one vers:DocumentData to another
     */
    private boolean checkLink(Node n, String name) {
        Node attr, n1;
        boolean passed = true;
        String id;

        // get attribute value
        attr = findAttribute(n, name);
        if (attr != null) {

            // if link is to a version 1 VEO prepend 'v1-'
            if (name.equals("vers:forContentSeeOriginalDocumentAndEncoding")
                    || name.equals("vers:forContentsSeeOriginalDocumentAndEncoding")) {
                id = "v1-" + attr.getNodeValue();
            } else {
                id = attr.getNodeValue();
            }

            // document data must not contain a link and document data
            if (n.getFirstChild() != null) {
                startElementError("checkLink", 1, n, 133);
                continueError("A <vers:DocumentData> (M133) element cannot contain both content and a link (" + name + ") to another <vers:DocumentData> (M133) element");
                confirmError();
                passed = false;
            }

            // find the linked element
            n1 = (Node) nodeLabels.get(id);
            if (n1 == null) {
                startAttrError("checkLink", 2, n, 133, attr, true);
                continueError("Attribute does not reference another element");
                confirmError();
                return false;
            }

            // linked element must by a vers:DocumentData
            if (n1.getNodeType() != Node.ELEMENT_NODE || !n1.getNodeName().equals("vers:DocumentData")) {
                startAttrError("checkLink", 3, n, 133, attr, true);
                continueError("Attribute does not reference another <vers:DocumentData> (M133) element");
                confirmError();
                passed = false;
            }

            // linked document data element must contain actual data
            if (n1.getFirstChild() == null) {
                startAttrError("checkLink", 4, n, 133, attr, true);
                continueError("Attribute references a <vers:DocumentData> (M133) without content");
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
    private boolean checkValue(Node n, String value, String separator) {
        String s1;

        continueError("'" + value + "'" + separator);
        if (strict) {
            s1 = getValue(n).trim();
        } else {
            value = value.toLowerCase();
            s1 = getValue(n).trim().toLowerCase();
        }
        return value.equals(s1);
    }

    /**
     * Check the value in the node against the required value, ignoring case and
     * non-alphabetic characters. If test fails, add required value as an option
     * in the error message
     */
    private boolean checkValueRelaxed(Node n, String value, String separator) {
        continueError("'" + value + "'" + separator);
        return realValue(getValue(n)).equals(realValue(value));
    }

    /**
     * Extract the alphabetic characters from the value for comparison purposes.
     * This ignores non-alphabetic characters (e.g. whitespace, hyphens,
     * punctuation), and converts all alphabetic characters to lower case.
     */
    private String realValue(String value) {
        StringBuilder sb = new StringBuilder();
        int i, c;

        for (i = 0; i < value.length(); i++) {
            c = Character.codePointAt(value, i);
            if (Character.isAlphabetic(c)) {
                if (Character.isUpperCase(c)) {
                    sb.append(Character.toLowerCase(c));
                } else {
                    sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    /**
     * Compare the two values If strict, compare case, otherwise ignore case
     */
    private boolean equals(String s1, String s2) {
        if (!strict) {
            s1 = s1.toLowerCase();
            s2 = s2.toLowerCase();
        }
        return s1.equals(s2);
    }

    /**
     * TestSupport to see if an element has at least one immediate subordinate
     * of the specified type
     *
     * @param element	the element node to be searched
     * @param name	the name of the element to be found
     */
    private boolean testElementExists(Node element, String name) {
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
     *
     * An error is raised if the attribute is not found, or if it does not have
     * one of the valid values
     *
     * @param n	the element node the attribute is to be found in
     * @param name	the name of the attribute to find
     * @param id	the VERS specification number for the element
     * @param validvalues	an array of valid values for this attribute
     * @result false if the test failed (i.e. error raised)
     */
    private boolean testAttribute(String method, int errid, Node n, int id, String name, String[] validvalues) {
        Node a;
        int i;
        String s1, s2;

        // try to find attribute in node
        a = findAttribute(n, name);
        if (a == null) {
            startElementError(method, errid, n, id);
            continueError("   Element must contain a " + name + " attribute");
            confirmError();
            return false;
        }

        // try to find attribute value in list of valid values
        startAttrError(method, errid, n, id, a, true);
        continueError(" which must be: ");
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
            continueError("'" + validvalues[i] + "' ");
            if (i == validvalues.length - 2) {
                continueError("or ");
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
     * @param test - test method being called
     * @param id - base id
     * @param n the element in which the id must be found
     * @param mno the VERS specification number for the element (M number)
     */
    private boolean checkVersId(String test, int id, Node n, int mno) {
        String element, idVal;
        Node attr;
        String s[];

        element = n.getNodeName();

        // get vers:id attribute node
        attr = findAttribute(n, "vers:id");

        // error if version 1 and vers:id attribute present
        if (thisLayerVersion.equals("1.2")) {
            if (attr != null) {
                startV2inV1Error(test, id);
                continueError("<" + element + "> can only contain a vers:id attribute in a version 2.0 VEO");
                confirmError();
                return false;
            }
        }

        // error if version 2 and vers:id attribute not present
        if (attr == null) {
            startMissingAttrError(test, id+1);
            continueError("<" + element + "> must contain a vers:id attribute in a version 2 VEO");
            confirmError();
            return false;
        }

        // check vers:id for conformance to pattern
        idVal = attr.getNodeValue();
        startAttrError(test, id+2, n, mno, attr, true);
        continueError("The value ");
        s = idVal.split("-");
        if (element.equals("vers:RevisedVEO")) {
            if (s.length != 2
                    || !equals(s[0], "Revision")
                    || !testVersIdNumber(s[1])) {
                continueError("must match 'Revision-<int>'");
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
                continueError("must match 'Revision-<int>-Signature-<int>'");
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
                continueError("must match 'Revision-<int>-Document-<int>'");
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
                continueError("must match 'Revision-<int>-Document-<int>- Encoding-<int>'");
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
                continueError("must match 'Revision-<int>-Document-<int>- Encoding-<int>-DocumentData'");
                confirmError();
                return false;
            }
        }
        return true;
    }

    /**
     * Test to see if a string contains a number
     */
    private boolean testVersIdNumber(String s) {
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
    private boolean testDateValue(Node n, int id) {
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
                        startAttrError("testDateValue", 1, n, id, attr, true);
                        continueError("Attribute value should be 'ISO 8061.'");
                        confirmError();
                        return false;
                    }
                }
            }
        }

        // check value
        startValueError("testDateValue", 2, n, id, true);
        s = getValue(n).trim();
        if (s.length() < 4) {
            dateFailed("Year must match 'yyyy'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(0)))
                || !(Character.isDigit(s.charAt(1)))
                || !(Character.isDigit(s.charAt(2)))
                || !(Character.isDigit(s.charAt(3)))) {
            dateFailed("Year must match 'yyyy'");
            return false;
        }
        if (s.length() == 4) {
            return true;
        }

        if (s.length() < 7) {
            dateFailed("Month must match '-MM'");
            return false;
        }
        if (s.charAt(4) != '-') {
            dateFailed("separator between year and month must be '-'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(5)))
                || !(Character.isDigit(s.charAt(6)))) {
            dateFailed("Month must be two digits");
            return false;
        }
        i = Character.digit(s.charAt(5), 10) * 10 + Character.digit(s.charAt(6), 10);
        if (i < 1 || i > 12) {
            dateFailed("month must be in the range '01' to '12'");
            return false;
        }

        if (s.length() == 7) {
            return true;
        }

        if (s.length() < 10) {
            dateFailed("Day must match '-dd'");
            return false;
        }
        if (s.charAt(7) != '-') {
            dateFailed("separator between month and day must be '-'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(8)))
                || !(Character.isDigit(s.charAt(9)))) {
            dateFailed("day must be two digits");
            return false;
        }
        i = Character.digit(s.charAt(8), 10) * 10 + Character.digit(s.charAt(9), 10);
        if (i < 1 || i > 31) {
            dateFailed("day must be in the range '01' to '31'");
            return false;
        }

        if (s.length() == 10) {
            return true;
        }

        if (s.length() < 20) {
            dateFailed("Times must match 'Thh:mm:ssZ[xx:yy]'");
            return false;
        }

        if (s.charAt(10) != 'T') {
            dateFailed("separator between day and hour must be 'T'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(11)))
                || !(Character.isDigit(s.charAt(12)))) {
            dateFailed("hour must be two digits");
            return false;
        }
        if (Character.digit(s.charAt(11), 10) * 10 + Character.digit(s.charAt(12), 10) > 23) {
            dateFailed("hour must be in the range '00' to '23'");
            return false;
        }

        if (s.charAt(13) != ':') {
            dateFailed("separator between hour and minutes must be ':'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(14)))
                || !(Character.isDigit(s.charAt(15)))) {
            dateFailed("minutes must be two digits");
            return false;
        }
        if (Character.digit(s.charAt(14), 10) * 10 + Character.digit(s.charAt(15), 10) > 59) {
            dateFailed("minutes must be in the range '00' to '59'");
            return false;
        }

        if (s.charAt(16) != ':') {
            dateFailed("separator between minutes and seconds must be ':'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(17)))
                || !(Character.isDigit(s.charAt(18)))) {
            dateFailed("seconds must be two digits");
            return false;
        }
        if (Character.digit(s.charAt(17), 10) * 10 + Character.digit(s.charAt(18), 10) > 59) {
            dateFailed("seconds must be in the range '00' to '59'");
            return false;
        }

        if ((s.charAt(19) == 'Z' || s.charAt(19) == 'z') && s.length() == 20) {
            return true;
        }

        if (!(s.charAt(19) == '+' || s.charAt(19) == '-')) {

            dateFailed("Timezone after time must be 'Z' or '+hh:mm' or '-hh:mm'");
            return false;
        }

        if (s.length() < 25) {
            dateFailed("Timezones must match 'mm:ss'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(20)))
                || !(Character.isDigit(s.charAt(21)))) {
            dateFailed("hours in timezone must be two digits");
            return false;
        }
        if (Character.digit(s.charAt(20), 10) * 10 + Character.digit(s.charAt(21), 10) > 14) {
            dateFailed("hours in timezone must be in the range '00' to '14'");
            return false;
        }

        if (s.charAt(22) != ':') {
            dateFailed("separator between hours and minutes in timezone must be ':'");
            return false;
        }
        if (!(Character.isDigit(s.charAt(23)))
                || !(Character.isDigit(s.charAt(24)))) {
            dateFailed("minutes in timezone must be two digits");
            return false;
        }
        if (Character.digit(s.charAt(23), 10) * 10 + Character.digit(s.charAt(24), 10) > 59) {
            dateFailed("minutes in timezone must be in the range '00' to '59'");
            return false;
        }
        return true;
    }

    /**
     * Generic date message
     */
    private void dateFailed(String err) {
        continueError(err);
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
    private void startElementError(String method, int errid, Node n, int id) {
        startError(method, errid, "Error in element <" + n.getNodeName() + "> (M" + id + ")");
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
    private void startAttrError(String method, int errid, Node element, int id, Node attr, boolean printValue) {
        StringBuffer sb;

        sb = new StringBuffer();
        sb.append("Attribute error in <");
        sb.append(element.getNodeName());
        sb.append(" ");
        sb.append(attr.getNodeName() + " ");
        if (printValue) {
            sb.append("=\"" + attr.getNodeValue() + "\"");
        }
        sb.append("> (M" + id + ")");
        startError(method, errid, sb.toString());
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
    private void startValueError(String method, int errid, Node n, int id, boolean printValue) {
        String s;
        StringBuffer sb;

        sb = new StringBuffer();
        sb.append("Element error in <" + n.getNodeName() + "> (M" + id + "):");
        if (printValue) {
            sb.append(" Value is ");
            s = getValue(n);
            if (s.equals("") || s.equals(" ")) {
                sb.append("<empty>");
            } else {
                sb.append("\"" + s + "\"");
            }
        }
        startError(method, errid, sb.toString());
    }

    /**
     * Start a tentative error message about a missing element that is mandatory
     * in version 2
     */
    private void startV2MissingError(String method, int errid) {
        startError(method, errid, "Element that is mandatory in a version 2 VEO is missing");
    }

    /**
     * Start a tentative error message about a missing element that is mandatory
     * in version 1
     */
    private void startV1MissingError(String method, int errid) {
        startError(method, errid, "Element that is mandatory in a version 1 VEO is missing");
    }

    /**
     * Start a tentative error message about a mandatory missing element
     */
    private void startMissingError(String method, int errid) {
        startError(method, errid, "Missing mandatory element");
    }

    /**
     * Start a tentative error message about a V2 feature in a V1 VEO
     */
    private void startV2inV1Error(String method, int errid) {
        startError(method, errid, "Version 2 feature in a version 1 VEO");
    }

    /**
     * Start a tentative error message about a V1 feature in a V2 VEO
     */
    private void startV1inV2Error(String method, int errid) {
        startError(method, errid, "Version 1 feature in a version 2 VEO");
    }

    /**
     * Start a tentative error message about a missing mandatory attribute in a
     * V2 VEO
     */
    private void startMissingAttrError(String method, int errid) {
        startError(method, errid, "Missing mandatory attribute in a version 2 VEO");
    }

    /**
     * Start an error message for a check value
     */
    private String method;
    private int errid;

    private void startError(String method, int errid, String s) {
        this.method = method;
        this.errid = errid;
        errorMsg.setLength(0);
        errorMsg.append(s + ": ");
    }

    /**
     * Continue an error message
     */
    private void continueError(String s) {
        errorMsg.append(s);
    }

    /**
     * We have decided the error actually did occur, so print it
     */
    private void confirmError() {
        failed("TestValues", method, errid, errorMsg.toString());
        /*
        VEOFailure vf;
        
        vf = new VEOFailure("TestValues", method, errid, errorMsg.toString());
        addError(vf);
        // print(errorMsg.toString() + "\r\n");
        if (results != null) {
            results.recordResult(Type.ERROR, "FAILURE: INVALID VALUE: " + errorMsg.toString(), veoName, null);
        }
         */
    }

    /**
     * Must override...
     *
     * @return
     */
    @Override
    public String toString() {
        return null;
    }
}
