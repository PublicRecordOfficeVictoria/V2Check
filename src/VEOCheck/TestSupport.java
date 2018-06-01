/*
 * Copyright Public Record Office Victoria 2005, 2018
 * Licensed under the CC-BY license http://creativecommons.org/licenses/by/3.0/au/
 * Author Andrew Waugh
 */

package VEOCheck;

/**
 * *************************************************************
 *
 * T E S T
 *
 * This abstract class defines the behaviour of a test on a VEO. It also
 * includes a number of utility classes useful for many tests.
 *
 * <ul>
 * <li>20170108 getValue() now returns a space instead of null if node is not
 * recognised<\li>
 * <li>20150518 Imported into NetBeans.<\li>
 * <li>20180601 Now uses VERSCommon instead of VEOSupport
 * </ul>
 *
 * Andrew Waugh Copyright 2005, PROV
 *
 *************************************************************
 */
import org.w3c.dom.*;
import VERSCommon.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class is the abstract parent class for a test on a VEO
 *
 * @author Andrew Waugh
 */
public abstract class TestSupport {

    static protected String className = "VEOCheckII.VEOCheck"; // name of this class -- used for exception messages
    protected boolean verbose;  // true if verbose output is required
    protected boolean oneLayer; // true if only test outer layer of the VEO
    protected boolean strict;   // true if test strictly according to standard
    protected boolean da;       // true if test according to what the da will accept
    Writer out;                 // output of results
    private String test;        // test being carried out
    private final StringBuffer details; // temporary repository of results while test is running
    protected boolean success;  // true if tests all succeeded

    // logging
    private final static Logger LOG = Logger.getLogger("VEOCheck.TestSupport");

    /**
     * Base constructor
     *
     * @param verbose
     * @param strict
     * @param da
     * @param oneLayer
     * @param out
     */
    public TestSupport(boolean verbose, boolean strict, boolean da, boolean oneLayer, Writer out) {
        this.verbose = verbose;
        this.strict = strict;
        this.da = da;
        this.oneLayer = oneLayer;
        this.out = out;
        test = "";
        details = new StringBuffer();
        success = true;
    }

    /**
     * Set the output writer at the start of a series of tests
     *
     * @param out
     */
    public void setOutput(Writer out) {
        this.out = out;
    }

    /**
     * Return name of test
     *
     * @return
     */
    abstract public String getName();

    /**
     * Print the TestSupport Header
     *
     * Print an overall header for this test
     *
     * @param heading
     */
    protected void printTestHeader(String heading) {
        if (verbose) {
            try {
                out.write(heading);
                out.write("\r\n");
            } catch (IOException ioe) {
                LOG.log(Level.WARNING, "VEOCheck.printTestHeader(): failed:  {0}", new Object[]{ioe.toString()});
            }
        }
    }

    /**
     * Start a new subtest
     *
     * Used by the subclasses to start a new test. Output of the test will be
     * accumulated until the result of the test is known
     *
     * @param heading
     */
    protected void startSubTest(String heading) {
        details.setLength(0);
        test = heading;
    }

    /**
     * Cancel a subtest
     *
     * Used by subclasses when a subtest didn't require any report
     */
    protected void cancelSubTest() {
        test = "";
        details.setLength(0);
    }

    protected void failed(String mesg) {
        try {
            out.write("FAILURE: ");
            out.write(test);
            out.write(": ");
            out.write(mesg);
            if (mesg.length() > 0) {
                out.write(": ");
            }
            out.write(details.toString());
            out.write("\r\n");
        } catch (IOException ioe) {
            LOG.log(Level.WARNING, "VEOCheck.failed(): failed:  {0}", new Object[]{ioe.toString()});
        }
        success = false;
        test = "";
        details.setLength(0);
    }

    /**
     * Report a success
     *
     * @param mesg a message to print about test
     */
    protected void passed(String mesg) {

        try {
            out.write("Success: ");
            out.write(test);
            out.write(": ");
            out.write(mesg);
            out.write("\r\n");
            if (verbose) {
                out.write(details.toString());
                out.write("\r\n");
            }
        } catch (IOException ioe) {
            LOG.log(Level.WARNING, "VEOCheck.passed(): failed:  {0}", new Object[]{ioe.toString()});
        }
        test = "";
        details.setLength(0);
    }

    /**
     * Check to see a node is empty. An empty element either has no children, or
     * all the children are empty An empty text node either contains nothing or
     * only whitespace.
     *
     * @param n
     * @return
     */
    public boolean elementIsEmpty(Node n) {
        Node child;
        String s;

        // an element is empty if none of its children (if any) contain content
        if (n.getNodeType() == Node.ELEMENT_NODE) {
            child = n.getFirstChild();
            while (child != null) {
                if (!elementIsEmpty(child)) {
                    return false;
                }
                child = child.getNextSibling();
            }
            return true;

            // a text node is empty if it contains nothing or whitespace
        } else if (n.getNodeType() == Node.TEXT_NODE) {
            s = n.getNodeValue().trim();
            if (s.equals("") || s.equals(" ")) {
                return true;
            }
        }
        return false;
    }

    /**
     * Search this element for the specified element. Passed the element to
     * search (e) and the tag name to find (tag). Returns the string contents of
     * the element. Won't work if contents are not a string. Will only return
     * first element if there are multiples...
     *
     * @param e
     * @param tag
     * @return
     */
    public String getElementContents(Element e, String tag) {
        Node n, child;
        String s;

        // get instances of requested element within e
        n = findElement(e, tag);
        if (n == null) {
            return (String) null;
        }

        // get contents of first element; if element contains a vers:Text node
        // go through it
        child = n.getFirstChild();
        s = null;
        while (child != null) {
            if (child.getNodeType() == Node.ELEMENT_NODE
                    && child.getNodeName().equals("vers:Text")) {
                child = child.getFirstChild();
                s = null;
                continue;
            }
            if (child.getNodeType() == Node.TEXT_NODE) {
                if (s == null) {
                    s = child.getNodeValue();
                } else {
                    s = s + child.getNodeValue();
                }
            }
            child = child.getNextSibling();
        }
        return s;
    }

    /**
     * Get the value from a node Recursively collects together the contents of
     * any text subordinate nodes to node
     *
     * @param n
     * @return
     */
    public String getValue(Node n) {
        Node child;
        StringBuilder sb;

        // if value is a vers:Text element, look through it
        if (n.getNodeType() == Node.ELEMENT_NODE) {
            sb = new StringBuilder();
            child = n.getFirstChild();
            while (child != null) {
                sb.append(getValue(child));
                child = child.getNextSibling();
            }
            return sb.toString().trim();
        }

        // look at contents
        if (n.getNodeType() == Node.TEXT_NODE) {
            return n.getNodeValue();
        }

        return " ";
        // return null;
    }

    /**
     * Find an attribute
     *
     * This finds the instance of the attribute within the node, returning null
     * if none is found
     */
    Node findAttribute(Node n, String attrName) {
        NamedNodeMap attrs;
        Node attr;
        int i;

        // find attribute node
        attrs = n.getAttributes();
        for (i = 0; i < attrs.getLength(); i++) {
            attr = attrs.item(i);
            if (attr.getNodeName().equals(attrName)) {
                return attr;
            }
        }

        // not found return null
        return null;
    }

    /**
     * Find an element
     *
     * This finds the instance of an element within the node, returning null if
     * none is found
     */
    Node findElement(Element e, String tag) {
        NodeList nl;
        Node n;

        // get instances of requested element within e
        nl = e.getElementsByTagName(tag);
        if (nl.getLength() == 0) {
            return null;
        }

        // get first instance of requested element
        n = nl.item(0);
        if (n.getNodeType() != Node.ELEMENT_NODE) {
            LOG.log(Level.WARNING, "*****PANIC in VEOCheck.VEOTest.getElementContents(): Error in DOM; Looking for {0}", new Object[] {tag});
            return null;
        }
        return n;
    }

    /**
     * Search this element for the specified element and return contents as byte
     * array (assumes contents are enconded as Base64). Passed the element to
     * search (e) and the tag name to find (tag). Returns the string contents of
     * the element. Won't work if contents are not a string. Will only return
     * first element if there are multiples...
     *
     * @param e
     * @param tag
     * @return
     */
    public byte[] getElementContentsAsByte(Element e, String tag) {
        ByteArrayOutputStream baos;
        OutputStreamWriter osw;
        B64 b64c = new B64();
        byte[] r;
        String s;

        s = getElementContents(e, tag);
        if (s.equals((String) null)) {
            return (byte[]) null;
        }
        s = s.trim();
        if (s.equals("")) {
            return (byte[]) null;
        }
        try {
            baos = new ByteArrayOutputStream();
            osw = new OutputStreamWriter(baos, "8859_1");
            osw.write(s);
            osw.close();
            r = b64c.fromBase64(baos.toByteArray());
        } catch (IOException ioe) {
            LOG.log(Level.WARNING, "*****PANIC in VEOCheck.VEOTest.getElementContents(): {0}", new Object[] {ioe.toString()});
            return (byte[]) null;
        }
        return r;
    }

    /**
     * Debug output
     *
     * @param s
     */
    protected void pdebug(String s) {
        int t;
        
        t = (int) Math.floor(System.currentTimeMillis() / 1000);
        LOG.log(Level.WARNING, "{0} {1}", new Object[]{t, s});
    }

    /**
     * Return current date as a string.
     *
     * @param tz timezone
     * @return date as a String
     */
    public String getDate(String tz) {
        java.text.DateFormat df;

        // df = new java.text.SimpleDateFormat("yyyyMMdd:hhmmssz");
        df = new java.text.SimpleDateFormat("dd MMM yyyy hh:mm '('z')'");
        df.setTimeZone(java.util.TimeZone.getTimeZone(tz));
        return df.format(new java.util.Date());
    }

    /**
     * Print a string to the temporary buffer.
     *
     * @param s the string to print
     */
    protected void print(String s) {
        details.append(s);
    }

    /**
     * Print a character to the temporary buffer.
     *
     * @param c the character to print
     */
    protected void print(char c) {
        details.append(c);
    }

    /**
     * Print a string to the temporary buffer following by a new line.
     *
     * @param s the string to print
     */
    protected void println(String s) {
        print(s);
        print("\r\n");
    }

    /**
     * Break the line
     */
    protected void printnl() {
        print("\r\n");
    }

    /**
     * Print a non breaking space
     */
    protected void printsp() {
        print(' ');
    }
}
