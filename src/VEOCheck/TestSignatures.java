/*
 * Copyright Public Record Office Victoria 2005, 2018
 * Licensed under the CC-BY license http://creativecommons.org/licenses/by/3.0/au/
 * Author Andrew Waugh
 */
package VEOCheck;

/**
 * *************************************************************
 *
 * T E S T S I G N A T U R E S
 *
 * This class tests the signatures in a VEO. It verifies the various signatures
 * using the various information in the VEO
 *
 * Todo one day: Produce output if signature verification succeeds Test to see
 * if lock signature is signing vers:Signature tags
 *
 * Andrew Waugh Copyright 2005 PROV
 *
 * <ul>
 * <li>20150518 Imported into NetBeans.<\li>
 * <li>20101027 Added tests to deal with 2nd and subsequent certificates not
 * decoding correctly (e.g. empty element)<\li>
 * <li>20180406 Altered finaliseVerification() to print debug information if
 * loading the signature failed (e.g. due to signature format failure)</li>
 * <li>20180406 Revised logging and reporting </li>
 * <li>20180601 Now uses VERSCommon instead of VEOSupport
 * <li>20190909 Added support for SHA-384
 * </ul>
 *
 *************************************************************
 */
import VERSCommon.*;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TestSignatures extends TestSupport {

    // state machine
    TSState[] tsstate = new TSState[30];

    // lock signature block and signature blocks
    SigChecker root;        // root of verifier checkers
    SigChecker sigBlockList;// list of signature blocks currently found at this level
    SigChecker lockSigBlock;// lock signature block

    // temporary information we collect as we parse a signature block
    // or lock signature block
    SigChecker sigBlock;    // information about a signature block
    ArrayList<String> certChain; // information about a certificate chain

    // converter from Base64
    static B64 b64c = new B64();

    // character decoder
    CharsetDecoder cd;

    // true when processing a signed object in a vers:RevisedVEO
    boolean ignoreSignedObject;

    // until first vers:Signature block is found
    boolean firstSignatureBlock;

    // logging
    private final static Logger LOG = Logger.getLogger("VEOCheck.TestSignatures");
    boolean debug;      // true if debugging

    /**
     * Constructor
     *
     * @param verbose
     * @param debug
     * @param strict
     * @param da
     * @param oneLayer
     * @param out
     */
    public TestSignatures(boolean verbose, boolean debug, boolean strict,
            boolean da, boolean oneLayer, Writer out) {
        super(verbose, strict, da, oneLayer, out);
        this.debug = debug;

        // set up state machine
        // match 'vers:SignatureBlock', 'vers:LockSignatureBlock', or
        // 'vers:SignedObject'
        tsstate[0] = new TSState(false, false, "<", 1, 0);
        tsstate[1] = new TSState("v", 2, "/", 28, 0);
        tsstate[2] = new TSState(false, false, "ers:", 3, 0);
        tsstate[3] = new TSState("S", 4, "L", 10, 0);
        tsstate[4] = new TSState(false, false, "ign", 5, 0);
        tsstate[5] = new TSState("a", 6, "e", 27, 0);
        tsstate[6] = new TSState(false, false, "tureBlock", 7, 0);
        tsstate[7] = new TSState("v", 8, ">", 13, 0);
        tsstate[8] = new TSState(false, true, "ers:id=\"", 9, 0);
        tsstate[9] = new TSState(true, true, "\"", 13, 0);

        tsstate[10] = new TSState(false, false, "ockSignatureBlock", 11, 0);
        tsstate[11] = new TSState(false, true, "vers:signsSignatureBlock=\"", 12, 0);
        tsstate[12] = new TSState(true, true, "\"", 13, 0);

        // matched 'vers:SignatureBlock', 'vers:LockSignatureBlock'
        // get signature algorithm identifier, and signature, and certificates
        tsstate[13] = new TSState(false, true, "<vers:SignatureAlgorithmIdentifier>", 14, 0);
        tsstate[14] = new TSState(true, true, "<", 15, 0);
        tsstate[15] = new TSState(false, true, "<vers:Signature>", 16, 0);
        tsstate[16] = new TSState(true, true, "<", 17, 0);
        tsstate[17] = new TSState(false, true, "<", 18, 0);
        tsstate[18] = new TSState("v", 19, "/", 0, 0);
        tsstate[19] = new TSState(false, false, "ers:CertificateBlock>", 20, 0);
        tsstate[20] = new TSState(false, true, "<", 21, 0);
        tsstate[21] = new TSState("v", 22, "/", 17, 0);
        tsstate[22] = new TSState(false, false, "ers:", 23, 0);
        tsstate[23] = new TSState("C", 24, "S", 25, 0);
        tsstate[24] = new TSState(false, false, "ertificate>", 26, 0);
        tsstate[25] = new TSState(false, false, "ignersCertificate>", 26, 0);
        tsstate[26] = new TSState(true, true, "<", 20, 0);

        // matched 'vers:SignedObject'
        tsstate[27] = new TSState(false, false, "dObject", 0, 0);

        // matched 'vers:SignedObject' end tag
        tsstate[28] = new TSState(false, false, "vers:SignedObject>", 0, 0);

        // set up other globals
        sigBlock = null;
        lockSigBlock = null;
        sigBlockList = null;
        root = null;
        ignoreSignedObject = false;
        firstSignatureBlock = true;

        // decoder from UTF-8
        cd = Charset.forName("UTF-8").newDecoder();
    }

    /**
     *
     * Return the name of this test
     *
     * @return name of test
     */
    @Override
    public String getName() {
        return "TestSignature";
    }

    /**
     * This class tests the signatures in a VEO.
     *
     * @param veo
     * @return true if all the signatures verified
     */
    public boolean performTest(File veo) {
        FileInputStream fis;
        BufferedInputStream bis;
        byte[] b;
        int c;
        int j;
        boolean failed = false;
        TSState state;
        StringBuffer sb;
        ByteBuffer bb;
        CharBuffer cb;
        CoderResult res;

        // reset the globals for a new run
        printTestHeader("Testing Signatures");
        success = true;
        root = null;
        sigBlockList = null;
        lockSigBlock = null;
        sigBlock = null;
        certChain = new ArrayList<>();
        ignoreSignedObject = false;
        firstSignatureBlock = true;

        // open the VEO for buffered reading
        if (veo == null) {
            LOG.log(Level.WARNING, "TestSignatures.performTest(): passed null file as VEO");
            return false;
        }
        try {
            fis = new FileInputStream(veo);
        } catch (FileNotFoundException fnfe) {
            LOG.log(Level.WARNING, "TestSignatures.performTest(): VEO file ''{0}'' not found", new Object[]{veo.getAbsolutePath()});
            return false;
        }
        bis = new BufferedInputStream(fis);

        // process each character in the VEO
        state = tsstate[0];
        sb = new StringBuffer();
        b = new byte[1];
        bb = ByteBuffer.wrap(b);
        char[] ca = new char[1];
        cb = CharBuffer.wrap(ca);
        // cb = CharBuffer.allocate(1);
        cd.reset();
        j = 0;
        try {
            while (bis.read(b, 0, 1) != -1) {

                // ignore whitespace (space, tab, carriage return, or new line
                // assumes file is encoded using UTF-8 so these characters are
                // ASCII
                if (b[0] == 0x20 || b[0] == 0x09 || b[0] == 0x0D || b[0] == 0x0A) {
                    continue;
                }

                // write c to top signature checker
                if (root != null) {
                    root.nextChar(b[0]);
                }

                // convert bytes to character
                res = cd.decode(bb, cb, false);
                c = cb.get(0);

                /*
                System.err.print(String.format("%02X ", b[0]) + " ");
                s.append((char) c);
                x++;
                if (x == 32) {
                    System.err.print(s.toString());
                    System.err.print("\n");
                    s.setLength(0);
                    x = 0;
                }
                 */
                cb.clear();
                bb.clear();

                // record character...
                if (state.isRecording()) {
                    sb.append((char) c);
                }

                // process this character in current state
                if (!state.isChoice()) {
                    if (c == state.getStr().charAt(j)) {
                        j++;
                        if (j == state.getStr().length()) {
                            failed |= !performAction(state, ' ', sb);
                            // pdebug("Matched '"+state.getStr()+"' "+state.getNextStateMatched());
                            state = tsstate[state.getNextStateMatched()];
                            sb.setLength(0);
                            j = 0;
                        }
                    } else if (!state.isSkip()) {
                        // if (state != tsstate[0])
                        // pdebug("Failed '"+state.getStr()+"' "+state.getNextStateFailed());
                        state = tsstate[state.getNextStateFailed()];
                        sb.setLength(0);
                        j = 0;
                    } else {
                        j = 0;
                    }
                } else {
                    failed |= !performAction(state, (char) c, sb);
                    state = tsstate[state.getNextStateChoice((char) c)];
                    sb.setLength(0);
                    j = 0;
                }
            }
        } catch (IOException ioe) {
            LOG.log(Level.WARNING, "TestSignatures.performTest(): Error when reading VEO: {0}", new Object[]{ioe.getMessage()});
            failed = true;
        } finally {
            cd.decode(bb, cb, true);
            cd.flush(cb);
            try {
                bis.close();
                // isr.close();
                fis.close();
            } catch (IOException e) {
                /* ignore */ }
        }
        if (!failed) {
            startSubTest("TESTING SIGNATURES");
            passed("All signatures tested are valid");
        }
        return success;
    }

    /**
     * Do a specific action upon a state transfer
     *
     * @param state	current state
     * @param c	character currently looking at
     * @param sb	characters we have seen in this state
     * @return true if the action succeeded
     *
     * This method is called just before a state transition. It is passed the
     * current state and, if a choice, the current character.
     */
    private boolean performAction(TSState state, char c, StringBuffer sb) throws IOException {
        String s;
        SigChecker sc;

        // found a vers:SignatureBlock
        if (state == tsstate[5] && c == 'a') {
            // pdebug("Found vers:SignatureBlock");
            if (!oneLayer || firstSignatureBlock) {
                sigBlock = new SigChecker(true, false);
            } else {
                sigBlock = new SigChecker(false, false);
            }
            firstSignatureBlock = false;
            return true;
        }

        // found a vers:LockSignatureBlock
        if (state == tsstate[10]) {
            // pdebug("Found vers:LockSignatureBlock");
            sigBlock = new SigChecker(true, true);
            return true;
        }

        // found a vers:id within a vers:SignatureBlock
        if (state == tsstate[9]) {
            s = sb.toString();
            // pdebug("Found vers:id: "+s);
            sigBlock.setId(s.substring(0, s.length() - 1));
            return true;
        }

        // found a vers:signsSignatureBlock within a vers:LockSignatureBlock
        if (state == tsstate[12]) {
            s = sb.toString();
            // pdebug("Found vers:signsSignatureBlock: "+s);
            sigBlock.setId(s.substring(0, s.length() - 1));
            return true;
        }

        // found a vers:SignatureAlgorithmIdentifer
        if (state == tsstate[14]) {
            s = sb.toString();
            // pdebug("Found vers:SignatureAlgorithmIdentifier: "+s);
            sigBlock.setSigAlgId(s.substring(0, s.length() - 1));
            return true;
        }

        // found a vers:Signature
        if (state == tsstate[16]) {
            s = sb.toString();
            // pdebug("Found vers:Signature: "+s);
            sigBlock.setSignature(s);
            return true;
        }

        // found a vers:CertificateBlock start element
        if (state == tsstate[18] && c == 'v') {
            // pdebug("Found vers:CertificateBlock start element");
            certChain = new ArrayList<>();
            return true;
        }

        // found a vers:SignatureBlock or vers:LockSignatureBlock end element
        if (state == tsstate[18] && c == '/') {
            // pdebug("Found Sig Block"+ sigBlock.toString());
            if (!sigBlock.setUpVerification()) {
                return false;
            }

            // remember this signature block
            if (sigBlock.isLockSig()) {
                lockSigBlock = sigBlock;
            } else {
                sigBlock.setNext(sigBlockList);
                sigBlockList = sigBlock;
            }
            sigBlock = null;
            return true;
        }

        // found a vers:CertificateBlock end element
        if (state == tsstate[21] && c == '/') {
            // pdebug("Found </vers:CertificateBlock");
            sigBlock.addCertChain(certChain);
            certChain = null;
            return true;
        }

        // found a vers:Certificate
        if (state == tsstate[26]) {
            s = sb.toString();
            // pdebug("Found vers:Certificate: "+s);
            certChain.add(s.substring(0, s.length() - 1));
            return true;
        }

        // found a vers:SignedObject start tag
        if (state == tsstate[27]) {
            // pdebug("Found vers:SignedObject start tag");

            // if we haven't seen a signature block, must be vers:RevisedVEO
            if (sigBlockList == null) {
                ignoreSignedObject = true;
                return true;
            }

            // chain lock signature block off proper signature block
            boolean failed = false;
            if (lockSigBlock != null) {
                sc = sigBlockList;
                while (sc != null) {
                    if (sc.getId().equals(lockSigBlock.getId())) {
                        sc.setLockSig(lockSigBlock);
                        lockSigBlock = null;
                        break;
                    }
                    sc = sc.next;
                }
                if (sc == null) {
                    startSubTest("TESTING SIGNATURES");
                    failed("Lock signature validation failed: The Lock Signature purports to sign vers:Signature element with vers:id '" + lockSigBlock.getId() + "' but this element does not exist");
                    failed = true;
                }
            }

            // output preamble that we have already seen...
            sigBlockList.initialiseVerification("<vers:SignedObject");

            // chain signature blocks at top of stack
            sigBlockList.setChild(root);
            root = sigBlockList;
            sigBlockList = null;
            return !failed;
        }

        // found a vers:SignedObject end tag
        if (state == tsstate[28]) {
            // pdebug("Found vers:SignedObject end tag\r\n");

            // if ignoreSignedObject is set, we are actually processing a
            // signed object in a vers:RevisedVEO element... so ignore
            // this end tag
            if (ignoreSignedObject) {
                ignoreSignedObject = false;
                return true;
            }

            // otherwise pop the top set of signature checkers off stack
            sc = root;
            root = sc.getChild();
            sc.setChild(null);

            // finalise top set of signature checkers
            return sc.finaliseVerification();
        }

        return true;
    }

    /**
     * Class documenting a state
     *
     * This state contains the information about a state.
     *
     * For a state that is attempting to match a string (e.g.
     * '<vers:SignedObject>') the information is the string to match, the next
     * state if the match succeeds or fails
     *
     * For a state that is attempting to choose amongst several paths, the
     * information is the set of choice characters, and the states to go to if
     * one of the characters matches, and the next state if all the matches
     * fail. Currently can only have two options.
     */
    public class TSState {

        private final boolean choice;	// true if this state chooses amongst paths
        private final String match[] = new String[2]; // string that this state is looking for
        private final int nextStateMatch[] = new int[2];// next state when matches
        private final int nextStateFail;// next state when match fails
        private final boolean recording;// true if recording characters in this state
        private boolean skip;	// true if other characters may occur before
        // matching this state

        // constructor for non-choice state
        public TSState(boolean recording, boolean skip,
                String matches, int nextStateMatch, int nextStateFail) {
            this.choice = false;
            this.recording = recording;
            this.skip = skip;
            this.match[0] = matches;
            this.nextStateMatch[0] = nextStateMatch;
            this.nextStateFail = nextStateFail;
        }

        // constructor for choice states
        public TSState(String match0, int nextStateMatch0,
                String match1, int nextStateMatch1,
                int nextStateFail) {
            this.choice = true;
            this.recording = false;
            this.match[0] = match0;
            this.nextStateMatch[0] = nextStateMatch0;
            this.match[1] = match1;
            this.nextStateMatch[1] = nextStateMatch1;
            this.nextStateFail = nextStateFail;
        }

        // get methods
        public boolean isChoice() {
            return choice;
        }

        public boolean isRecording() {
            return recording;
        }

        public boolean isSkip() {
            return skip;
        }

        public String getStr() {
            return match[0];
        }

        public int getNextStateMatched() {
            return nextStateMatch[0];
        }

        public int getNextStateFailed() {
            return nextStateFail;
        }

        public int getNextStateChoice(char c) {
            if (match[0].charAt(0) == c) {
                // pdebug("Selected "+c);
                return nextStateMatch[0];
            }
            if (match[1].charAt(0) == c) {
                // pdebug("Selected "+c);
                return nextStateMatch[1];
            }
            return nextStateFail;
        }
    }

    /**
     * S I G C H E C K E R
     *
     * This class encapsulates the verification of a signature.
     *
     * One SigChecker instance is created for each SignatureBlock or Lock
     * Signature Block in the VEO.
     *
     * Each signature block contains the signature algorithm id, the signature,
     * and the certificate chain to be used to verify the signature. The same
     * structure is used for a lock signature block and a normal signature block
     */
    private class SigChecker {

        StringBuffer em;	// place to put errors when performing check
        boolean isFirst;	// true if the first signature block found
        boolean isLockSig;	// true if lock signature
        String id;		// vers:Id
        String sigAlgId;	// signature algorithm identifier
        String signature;	// signature
        ArrayList<ArrayList<String>> certChain; // certificate chain
        SigChecker lockSig;	// lock signature block signing this signature
        SigChecker next;	// next signature checker at this level
        SigChecker child;	// pointer to first signature checker at next level
        Signature sig;		// wrapper around digital signature
        String sigAlgorithm;	// signature algorithm
        MessageDigest md;	// message digest
        String mdAlgorithm;	// signature algorithm
        X509Certificate x509c;	// X.509 certificate with signers public key
        // create temporary file to capture output
        File ft;

        // use the following when it is necessary to write out the byte stream
        // being verified
        /*
        FileOutputStream fos;
        Writer osw;
        BufferedWriter bw; */
        /**
         * Constructor
         *
         * @param lockSig true if this is a lock signature block
         */
        public SigChecker(boolean isFirst, boolean isLockSig) {
            em = new StringBuffer();
            this.isFirst = isFirst;
            this.isLockSig = isLockSig;
            id = null;
            sigAlgId = null;
            signature = null;
            certChain = new ArrayList<>();
            lockSig = null;
            next = null;
            child = null;
            sig = null;
            sigAlgorithm = null;
            md = null;
            mdAlgorithm = null;
            x509c = null;
        }

        /**
         * Is this the first signature block in a VEO?
         *
         * @returns true if this is the first signature block
         */
        public boolean isFirst() {
            return isFirst;
        }

        /**
         * Does this contain a lock signature block?
         *
         * @returns true if this contains a lock signature block
         */
        public boolean isLockSig() {
            return isLockSig;
        }

        /**
         * Set or get the vers:id or vers:signsSignatureBlock attribute
         */
        public void setId(String id) {
            this.id = id;
        }

        public String getId() {
            return id;
        }

        /**
         * Set or get the signature algorithm id
         */
        public void setSigAlgId(String sigAlgId) {
            this.sigAlgId = sigAlgId;
        }

        public String getSigAlgId() {
            return sigAlgId;
        }

        /**
         * Set the signature
         *
         * @parem signature	value of the vers:Signature element
         */
        public void setSignature(String signature) {
            this.signature = signature;
        }

        /**
         * Set the certificate chain
         *
         * @parem certChain	value of the vers:CertificateBlock element
         */
        public void addCertChain(ArrayList<String> certChain) {
            this.certChain.add(certChain);
        }

        /**
         * Set and get the next signature checker at this level
         */
        public void setNext(SigChecker next) {
            this.next = next;
        }

        public SigChecker getNext() {
            return next;
        }

        /**
         * Set and get the child signature checker at the next level
         */
        public void setChild(SigChecker child) {
            this.child = child;
        }

        public SigChecker getChild() {
            return child;
        }

        /**
         * Set and get the lock signature block
         */
        public void setLockSig(SigChecker lockSig) {
            this.lockSig = lockSig;
        }

        public SigChecker getLockSig() {
            return lockSig;
        }

        /**
         * Seen a complete signature block; set up the verification...
         *
         * This routine works out the signature algorithms used, and gets the
         * public key from the first certificate. If anything fails, complain.
         *
         * @return true if everything worked
         */
        public boolean setUpVerification() {
            ArrayList<String> v;

            // preamble to error message
            startSubTest("TESTING SIGNATURES");
            print("Validating ");
            if (isLockSig) {
                print("Lock Signature (signs vers:Signature \"" + id + "\")");
            } else if (id != null) {
                print("Signature (vers:id=\"" + id + "\")");
            } else {
                print("Signature (without vers:id)");
            }
            print(": ");

            // work out which algorithms were being used
            switch (sigAlgId) {
                case "1.2.840.10040.4.3":
                    sigAlgorithm = "SHA1withDSA";
                    mdAlgorithm = "SHA1";
                    break;
                case "1.2.840.113549.1.1.2":
                    sigAlgorithm = "MD2withRSA";
                    mdAlgorithm = "MD2";
                    break;
                case "1.2.840.113549.1.1.4":
                    sigAlgorithm = "MD5withRSA";
                    mdAlgorithm = "MD5";
                    break;
                case "1.2.840.113549.1.1.5":
                    sigAlgorithm = "SHA1withRSA";
                    mdAlgorithm = "SHA-1";
                    break;
                case "1.2.840.113549.1.1.11":
                    sigAlgorithm = "SHA256withRSA";
                    mdAlgorithm = "SHA-256";
                    break;
                case "1.2.840.113549.1.1.12":
                    sigAlgorithm = "SHA384withRSA";
                    mdAlgorithm = "SHA-384";
                    break;
                case "1.2.840.113549.1.1.13":
                    sigAlgorithm = "SHA512withRSA";
                    mdAlgorithm = "SHA-512";
                    break;
                default:
                    failed("The signature algorithm identifier ('" + sigAlgId + "') contained in the vers:SignatureAlgorithmIdentifier (M150) element is not recognised");
                    return false;
            }

            // extract public key from first certificate
            if (certChain.size() < 1) {
                failed("The signature block does not contain any vers:CertificateBlock (M139) elements");
                return false;
            }
            v = certChain.get(0);
            if (v.size() < 1 || v.get(0) == null) {
                failed("The first vers:CertificateBlock (M139) in the signature does not contain any vers:Certificate (M140) elements");
                return false;
            }
            x509c = extractCertificate(v.get(0));
            if (x509c == null) {
                failed("Could not decode the vers:Certificate (M140) in the first vers:CertificateBlock (M139) element");
                return false;
            }

            // set up verification...
            try {
                sig = Signature.getInstance(sigAlgorithm);
                sig.initVerify(x509c.getPublicKey());
                md = MessageDigest.getInstance(mdAlgorithm);
            } catch (NoSuchAlgorithmException nsae) {
                println("Security package does not support the signature or message digest algorithm. Error reported: " + nsae.getMessage());
                return false;
            } catch (InvalidKeyException ike) {
                failed("Security package reports that public key is invalid. Error reported: " + ike.getMessage());
                return false;
            }

            // set up file to write byte stream we are verifying
            // use this when attempting to work out why a signature is failing
            /*
            try {
                ft = File.createTempFile("SigDump", ".txt", new File("."));
                fos = new FileOutputStream(ft);
                osw = new OutputStreamWriter(fos, Charset.forName("UTF-8"));
                bw = new BufferedWriter(osw);
            } catch (IOException ioe) {
                failed("Failed trying to write dump file: " + ioe.getMessage());
                return false;
            } */
            // cancel the report on the sub test... initialising worked!
            cancelSubTest();
            return true;
        }

        /**
         * Decode a string containing base64 into an X.509 certifcate
         */
        private X509Certificate extractCertificate(String s) {
            CertificateFactory cf;
            ByteArrayInputStream bais;
            X509Certificate x509ci;
            byte[] b;
            int i;

            try {
                cf = CertificateFactory.getInstance("X.509");
                b = decodeB64String(s);
                bais = new ByteArrayInputStream(b);
                x509ci = (X509Certificate) cf.generateCertificate(bais);
                bais.close();
            } catch (CertificateException | IOException ce) {
                print("Error decoding certificate: " + ce.getMessage() + "\r\n");
                return null;
            }
            return x509ci;

        }

        /**
         * Decode a string containing base64 into a byte array
         */
        private byte[] decodeB64String(String s) throws IOException {
            ByteArrayOutputStream baos;
            OutputStreamWriter oswl;

            baos = new ByteArrayOutputStream();
            oswl = new OutputStreamWriter(baos, "8859_1");
            oswl.write(s);
            oswl.close();
            return b64c.fromBase64(baos.toByteArray());
        }

        /**
         * Initialise the verification
         */
        public void initialiseVerification(String s) {
            int i;

            // put the initial string
            for (i = 0; i < s.length(); i++) {
                nextChar(s.charAt(i));
            }
        }

        /**
         * Process the verification
         *
         * These routines are called to pass a character to the verification
         * method
         */
        public void nextChar(char c) {
            // hack; it is too slow to properly convert from unicode to ascii
            nextChar((byte) (c & 0xFF));
        }

        public void nextChar(byte b) {

            // use the following when it is necessary to output the byte stream
            // being verified
            /*
            try {
                bw.write((char) b);
            } catch (IOException ioe) {
                print("TestSignatures.nextChar(): IOException when writing output bytes to a file: " + ioe.getMessage());
            }
             */
            // update the digital signature calculation
            try {
                sig.update(b);
            } catch (SignatureException se) {
                print("TestSignatures.nextChar() signature update failed: " + se.getMessage());
            }
            md.update(b);

            // pass this character onto next signature block at this level
            if (next != null) {
                next.nextChar(b);
            }

            // pass the character onto first signature block at next level
            if (child != null) {
                child.nextChar(b);
            }
        }

        /**
         * Finalise the verification
         *
         * This function finalises the verification and complains if the
         * signature is not valid. It also verifies the certificate chains and,
         * if the signature is signed by a lock signature block, the lock
         * signature block.
         *
         * @return true if the signature and lock signature verified (including
         * the certificates)
         */
        public boolean finaliseVerification() throws IOException {
            int i;
            byte[] b, h;
            boolean passed;
            ArrayList<String> v;
            X509Certificate x509cl;
            char[] charbuf = {'0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
            String sigId;

            // use the following when outputing the byte stream to be verified
            /*
            try {
                bw.close();
                osw.close();
                fos.close();
            } catch (IOException ioe) {
                // ignore
            } */
            // ignore this signature if not the first and only processing one level
            if (!isFirst) {
                return true;
            }

            // which signature are we looking at?
            if (isLockSig) {
                sigId = "Lock Signature (signs vers:Signature \"" + id + "\")";
            } else if (id != null) {
                sigId = "Signature (vers:id=\"" + id + "\")";
            } else {
                sigId = "Signature (has no vers:id)";
            }

            // verify the signature...
            startSubTest("SIGNATURE");
            passed = true;
            b = decodeB64String(signature);
            try {
                if (!sig.verify(b)) {
                    // signature verification failed :-( 
                    print("Signature verification failed for " + sigId);
                    passed = false;
                } else if (verbose) {
                    // succeded, but only say if verbose
                    print(sigId + " VERIFIED :-)");
                }
            } catch (SignatureException se) {
                print("TestSignature.finaliseVerification() verify:" + se.getMessage());
                passed = false;
            }

            // dump the signature
            if (verbose) {
                println("");
                println("  Signature/Hash algorithm: "+sigAlgorithm);
                println("  Signature (base64): " + signature);
                print("  Signature (hex): ");
                for (i = 0; i < b.length; i++) {
                    print(charbuf[(b[i] >> 4) & 0x0f]);
                    print(charbuf[(b[i] & 0x0f)]);
                }
                println("");

                // calculate and print the message digest
                print("  Hash of signed object: ");
                h = md.digest();
                for (i = 0; i < h.length; i++) {
                    print(charbuf[(h[i] >> 4) & 0x0f]);
                    print(charbuf[(h[i] & 0x0f)]);
                }
                println("");

                // print the contents of the certificate
                if (certChain.size() < 1) {
                    print("No vers:CertificateBlock found\r\n");
                } else {
                    v = certChain.get(0);
                    if (v.size() < 1) {
                        print("No vers:Certificates found in first vers:CertificateBlock\r\n");
                    } else {
                        x509cl = extractCertificate(v.get(0));
                        if (x509cl != null) {
                            print("  Certificate: Subject: ");
                            print(x509cl.getSubjectDN().getName());
                            print(" issued by: ");
                            println(x509cl.getIssuerDN().getName());
                            println(x509cl.toString());
                        } else {
                            println("  Certificate: Empty");
                        }
                    }
                }

                // check DER encoding?
                // DER der = new DER(DER.INTEGER);
                // println("DER: "+der.toString(b, 0, b.length, 0));
                // if signature didn't work, check to see if signature
                // is reversed e.g. Microsoft's CryptoAPI
                if (!passed) {
                    println("");
                    for (i = 0; i < b.length / 2; i++) {
                        byte t = b[i];
                        b[i] = b[b.length - 1 - i];
                        b[b.length - 1 - i] = t;
                    }
                    println("");
                    try {
                        if (sig.verify(b)) {
                            print("The signature is reversed (i.e. the most significant\r\n");
                            print("octet is the last octet. Such signatures do not\r\n");
                            print("conform to RSA's PKCS #1. These signatures should\r\n");
                            print("be reversed when the VEO is generated.\r\n");
                        }
                    } catch (SignatureException se) {
                        print("TestSignature.finaliseVerification() verify:" + se.getMessage());
                        passed = false;
                    }
                }
            }

            // verify each certificate chain
            for (i = 0; i < certChain.size(); i++) {
                v = certChain.get(i);
                passed &= verifyCertificateChain(sigId, v);
            }

            // finish testing this signature checker itself
            if (!passed) {
                failed("");
            } else if (verbose) {
                passed("");
            } else {
                cancelSubTest();
            }

            // now verify lock signature (if present)
            if (lockSig != null) {
                if (!lockSig.setUpVerification()) {
                    return false;
                }
                lockSig.initialiseVerification(signature.substring(0, signature.length() - 1));
                passed &= lockSig.finaliseVerification();
            }

            return passed;
        }

        /**
         * Verify a certificate chain. Returns true if the certificate chain
         * verified
         */
        private boolean verifyCertificateChain(String sigId, ArrayList<String> chain) {
            int i;
            String s, issuer, subject;
            boolean passed;
            X509Certificate x509cl, signer;

            // get first certificate (to be verified)
            passed = true;
            if (chain.size() < 1) {
                print("No vers:Certificates (M140) found in first vers:CertificateBlock (M139) in " + sigId);
                return false;
            }
            x509cl = extractCertificate(chain.get(0));
            if (x509cl == (X509Certificate) null) {
                print("First certificate could not be extracted from " + sigId);
                println(" (it could be empty).");
                print("Remaining certificates have not been checked");
                return false;
            }
            subject = x509cl.getSubjectDN().getName();
            issuer = x509cl.getIssuerDN().getName();

            // verify chain
            for (i = 1; i < chain.size(); i++) {
                s = chain.get(i);
                signer = extractCertificate(s);
                if (signer == null) {
                    switch (i) {
                        case 1:
                            println("Could not decode the vers:Certificate (M140) in the second vers:CertificateBlock (M139) element in " + sigId);
                            break;
                        case 2:
                            println("Could not decode the vers:Certificate (M140) in the third vers:CertificateBlock (M139) element in " + sigId);
                            break;
                        default:
                            println("Could not decode the vers:Certificate (M140) in the " + i + "th vers:CertificateBlock (M139) element in " + sigId);
                            break;
                    }
                    print("Remaining certificates have not been checked");
                    return false;
                }
                if (!verifyCertificate(x509cl, signer)) {
                    println("Certificate " + (i - 1) + " of " + sigId + " failed verification ");
                    println("  Subject of certificate is: " + subject);
                    print("  Issuer of certificate is: " + issuer);
                    if (verbose) {
                        println("");
                        println("Certificate that failed verification:");
                        println(x509cl.toString());
                        println("Signing Certificate:");
                        println(signer.toString());
                    }
                    passed = false;
                }
                x509cl = signer;
            }

            // final certificate should be self signed...
            if (!verifyCertificate(x509cl, x509cl)) {
                print("Final certificate of " + sigId + " failed verification. ");
                if (!subject.equals(issuer)) {
                    println("Certificate is not self signed");
                } else {
                    println(" ");
                }
                println("  Subject of final certificate is: " + subject);
                print("  Issuer of final certificate is: " + issuer);
                if (verbose) {
                    println(" ");
                    println("Certificate that failed verification:");
                    print(x509cl.toString());
                }
                passed = false;
            }
            return passed;
        }

        /**
         * Verifies that the CA in the second certificate created the first
         * certificate. Returns true if the certificate verified.
         */
        private boolean verifyCertificate(X509Certificate first,
                X509Certificate second) {
            // println("First certificate: "+first.toString());
            try {
                first.verify(second.getPublicKey());
            } catch (SignatureException e) {
                failed("Signature of Certificate failed to verify: " + e.getMessage() + "\r\n");
                return false;
            } catch (CertificateException e) {
                failed("Problem with Certificate: " + e.getMessage() + "\r\n");
                return false;
            } catch (NoSuchAlgorithmException e) {
                failed("Problem with Certificate: No Such Algorithm: " + e.getMessage() + "\r\n");
                return false;
            } catch (InvalidKeyException e) {
                failed("Problem with Certificate: Invalid public key in Certificate: " + e.getMessage() + "\r\n");
                return false;
            } catch (NoSuchProviderException e) {
                failed("Problem with Certificate: No such provider: " + e.getMessage() + "\r\n");
                return false;
            }
            return true;
        }

        /**
         * Get the value of the signature block as a string
         *
         * @returns representation of the signature block as a string
         */
        @Override
        public String toString() {
            StringBuilder sb;
            int i, j;
            ArrayList<String> v;
            String s;

            sb = new StringBuilder();
            if (isLockSig) {
                sb.append("Lock Signature Block (signs=");
            } else {
                sb.append("Signature Block (id=");
            }
            if (id == null) {
                sb.append("no id specified)\r\n");
            } else {
                sb.append("'");
                sb.append(id);
                sb.append("')\r\n");
            }
            if (sigAlgId == null) {
                sb.append("  No signature algorithm present\r\n");
            } else {
                sb.append("  Signature Algorithm: '");
                sb.append(sigAlgId);
                sb.append("'\r\n");
            }
            if (signature == null) {
                sb.append("  No signature present\r\n");
            } else {
                sb.append("  Signature : '");
                sb.append(signature);
                sb.append("'\r\n");
            }
            if (certChain.isEmpty()) {
                sb.append("  No certificate chains present\r\n");
            } else {
                for (i = 0; i < certChain.size(); i++) {
                    sb.append("  Certificate chain (");
                    sb.append(i);
                    sb.append(")\r\n");
                    v = certChain.get(i);
                    if (v.isEmpty()) {
                        sb.append("    No certificates present\r\n");
                    } else {
                        for (j = 0; j < v.size(); j++) {
                            sb.append("    Certificate (");
                            sb.append(j);
                            sb.append(")\r\n");
                            s = v.get(j);
                            sb.append("      '");
                            sb.append(s);
                            sb.append("'\r\n");
                        }
                    }
                }
            }
            if (lockSig == null) {
                sb.append("  No lock signature\r\n");
            } else {
                sb.append("  Lock Signature : '");
                sb.append(lockSig);
                sb.append("'\r\n");
            }
            if (next == null) {
                sb.append("  No next signature block\r\n");
            } else {
                sb.append("  Next signature block: '");
                sb.append(next);
                sb.append("'\r\n");
            }
            if (child == null) {
                sb.append("  No child signature block\r\n");
            } else {
                sb.append("  Child signature block: '");
                sb.append(child);
                sb.append("'\r\n");
            }
            sb.append("  Errors detected: ");
            sb.append(em.toString());
            return sb.toString();

        }
    }
}
