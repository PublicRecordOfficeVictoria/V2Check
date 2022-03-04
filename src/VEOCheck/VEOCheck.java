/*
 * Copyright Public Record Office Victoria 2005, 2015, 2018
 * Licensed under the CC-BY license http://creativecommons.org/licenses/by/3.0/au/
 * Author Andrew Waugh
 */
package VEOCheck;

/**
 *
 * V E O C H E C K
 *
 * This class checks a VERS2 VEO for validity.
 *
 * @author Andrew Waugh (andrew.waugh@prov.vic.gov.au) Copyright 2005, 2015,
 * 2018 PROV
 *
 */
import VERSCommon.LTSF;
import VERSCommon.ResultSummary;
import VERSCommon.VEOError;
import VERSCommon.VEOFatal;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.TimeZone;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * This class checks that a VEO is valid. The class checks for (or will check
 * for!) the following:
 * <ul>
 * <li>Conformance to the DTD specified in the DOCTYPE element
 * <li>That the signatures are valid
 * <li>That the public keys are valid
 * <li>That the content can be extracted
 * <li>That content is not infected with viruses
 * </ul>
 * The class will also analyse the VEO for:
 * <ul>
 * <li>The present elements
 * <li>That present elements have legitimate values
 * <li>That there are no empty elements
 * </ul>
 */
public class VEOCheck {

    // name of this class -- used for exceptions messages
    private static final String CLASS_NAME = "VEOCheck.VEOCheck";

    // mode switch
    private boolean headless; // true if using in headless mode

    // command line arguments
    private final ArrayList<Path> files;
    private boolean strict;
    private boolean da;
    private boolean extract;
    private boolean virusCheck;
    private boolean mcafee;
    private int delay;
    private boolean parseVEO;
    private boolean useStdDtd;
    private Path dtd;
    private boolean oneLayer;
    private boolean testSignatures;
    private boolean testValues;
    private boolean version1;
    private boolean version2;
    private boolean verbose;
    private boolean debug;
    private boolean forceProgressReport;
    private LTSF ltsfs;
    boolean help;           // true if printing a cheat list of command line options

    // tests
    private ParseVEO parse;
    private TestValues valueTester;
    private TestSignatures signatureTester;
    private TestViruses virusTester;

    // output file
    private Path outputFile;

    // temporary directory
    private Path tempDir;

    // where to write results etc
    private Writer out;
    private ResultSummary results;

    // logging
    private final static Logger LOG = Logger.getLogger("VEOCheck.VEOCheck");

    /**
     * Report on version...
     *
     * <pre>
     * 20180601 2.0 Put under GIT
     * 20180620 2.1 Output the byteStream in test signatures
     * 20180711 2.2 Restructured packages
     * 20180831 2.3 Fixed bugs in reading non UTF-8 characters, now recurses through directories
     * 20181106 2.4 Now ignores DTD when pulling apart VEO
     * 20190108 2.5 Fix to possible bug
     * 20190819 2.6 Added support for SHA256 & SHA512
     * 20190919 2.7 Added support for SHA384 & general code cleanup
     * 20191127 2.8 Fixed bug, cleaned up BAT file & added Readme.md
     * 20191209 3.0 Added seven new security classifications
     * 20200103 3.1 Changed case 'Cabinet in confidence' a/c user request & redid BAT file
     * 20200207 3.2 Relaxed case checking in security classification a/c user request
     * 20200217 3.3 Simplified file name handling & corrected bug
     * 20200507 3.4 Added migration flag to support moving old VEOs into new DSA & added manual
     * 20200716 3.5 Moved to common code for LTSF checking for V2 and V3
     * 20200802 3.6 Support files are all now in VERS Common
     * 20200603 3.7 Added report summary functionality
     * 20200421 3.8 Now reports on missing and erroneous values in summary report
     * 20204030 3.9 Added -help command
     * 20210709 3.10 Added support for PISA (BAT file)
     * 20210712 3.11 Added check that the filename on command line exists & improved reporting
     * 20211001 3.12 Changed deprecated calls to get X509 issuer & subject
     * 20220202 3.13 Will now flag an error if vers:SourceFileIdentifier is not present (not invalid according to standard)
     * 20220304 3.14 Corrected a bug with the vers:SourceFileIdentifier check
     * </pre>
     */
    static String version() {
        return ("3.14");
    }

    /**
     * Constructor for testing outermost (first layer) of VEO.
     *
     * @param args command line arguments
     * @throws VERSCommon.VEOFatal could not be constructed
     */
    public VEOCheck(String args[]) throws VEOFatal {
        SimpleDateFormat sdf;
        TimeZone tz;

        // default logging
        LOG.getParent().setLevel(Level.WARNING);
        LOG.setLevel(null);

        headless = false;
        testSignatures = false;
        testValues = false;
        version1 = false;
        version2 = false;
        verbose = false;
        oneLayer = false;
        debug = false;
        strict = false;
        da = false;
        extract = false;
        virusCheck = false;
        mcafee = false;
        delay = 1;
        parseVEO = false;
        useStdDtd = false;
        dtd = null;
        files = new ArrayList<>();
        outputFile = null;
        tempDir = Paths.get(".");
        ltsfs = null;
        results = null;
        help = false;
        forceProgressReport = false;

        // parse commmand line arguments
        parseCommandArgs(args);

        // where do we write the output?
        if (outputFile == null) {
            out = new OutputStreamWriter(System.out);
        } else {
            try {
                out = new FileWriter(outputFile.toFile());
            } catch (IOException ioe) {
                throw new VEOFatal("Cannot open output file for writing: " + ioe.toString());
            }
        }

        // print out information about report
        try {
            out.write("******************************************************************************\r\n");
            out.write("*                                                                            *\r\n");
            out.write("*                 V E O ( V 2 )   T E S T I N G   T O O L                    *\r\n");
            out.write("*                                                                            *\r\n");
            out.write("*                                Version " + version() + "                                 *\r\n");
            out.write("*           Copyright 2005, 2015 Public Record Office Victoria               *\r\n");
            out.write("*                                                                            *\r\n");
            out.write("******************************************************************************\r\n");
            out.write("\r\n");

            System.out.println("Test run: ");
            tz = TimeZone.getTimeZone("GMT+10:00");
            sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss+10:00");
            sdf.setTimeZone(tz);
            out.write(sdf.format(new Date()));
            out.write("\r\n");
            if (help) {
                // VEOCheck [-all] -f LTSFFile [-strict] [-da] [-extract] [-virus] [-eicar] [-parseVEO] [-useStdDTD] [-dtd <dtdFile>] [-oneLayer] [-signatures] [-sr] [-values] [-v1.2|-v2] [-virus] [-verbose] [-debug] [-out <file>] [-t <tempDir>] <files>+";
                out.write("Command line arguments:\r\n");
                out.write(" Mandatory:\r\n");
                out.write("  -f <LTSfile>: file path to a file containing a list of the long term sustainable formats\r\n");
                out.write("  -t <directory>: file path to where the templates are located\r\n");
                out.write("  -dtd <dtdFile>: file path to the VERS V2 DTD for validation (usually set in BAT file)\r\n");
                out.write("  <files>: one or more files or directories containing VERS V2 VEOs\r\n");
                out.write("\r\n");
                out.write(" Optional:\r\n");
                out.write("  -all: do all tests (extract, signatures, values & virus)\r\n");
                out.write("  -extract: extract the content files from the VEO\r\n");
                out.write("  -signatures: validate the signatures\r\n");
                out.write("  -values: validate the element values in the VEO\r\n");
                out.write("  -virus: test to see if the content files are infected by a virus (requires an anti-virus program to be running)\r\n");
                out.write("  -sr: generate a report summarising the errors and warnings produced in validating multiple VEOs\r\n");
                out.write("  -tempdir <directory>: directory in which extracted content is left (& where work is performed)\r\n");
                out.write("  -out <file>: capture the output of the named run in the file\r\n");
                out.write("  -forceStatus: set if writing output to a file, this will also report on the console");
                out.write("\r\n");
                out.write(" Obsolete options:\r\n");
                out.write("  -parseVEO: parse the original VEO, not a copy stripped of its content files (much slower)\r\n");
                out.write("  -oneLayer: only validate the outer layer of a multi-layer VERS V2 VEO\r\n");
                out.write("  -strict: do the tests in strict accordance with the VERS 1999 Version 2 standard\r\n");
                out.write("  -da: do the tests as if it was the Digital Archive (default not set)\r\n");
                out.write("  -v1.2: validate against VERS V1.2 (default is V2)\r\n");

                out.write("\r\n");
                out.write("  -v: verbose mode: give more details about processing\r\n");
                out.write("  -d: debug mode: give even more details about processing\r\n");
                out.write("  -help: print this listing\r\n");
                out.write("\r\n");
            }

            out.write("Testing parameters:\r\n");
            if (extract) {
                out.write(" Extract content,\r\n");
            }
            if (testValues) {
                out.write(" Testing values,\r\n");
            }
            if (testSignatures) {
                out.write(" Testing signatures,\r\n");
            }
            if (virusCheck) {
                if (mcafee) {
                    out.write(" Testing for viruses using mcafee (delay =" + delay + "),\r\n");
                } else {
                    out.write(" Testing for viruses by generating EICAR files (delay =" + delay + "),\r\n");
                }
            }
            if (oneLayer) {
                out.write(" Only test outer layer,\r\n");
            }
            if (version1) {
                out.write(" Force test against version 1,\r\n");
            }
            if (version2) {
                out.write(" Force test against version 2,\r\n");
            }
            if (strict) {
                out.write(" Strict conformance to standard,\r\n");
            }
            if (da) {
                out.write(" Digital archive requirement,\r\n");
            }
            if (parseVEO) {
                out.write(" Parse original VEO not stripped copy,\r\n");
            }
            if (useStdDtd) {
                out.write(" Use standard DTD (http://www.prov.vic.gov.au/vers/standard/vers.dtd),\r\n");
            } else if (dtd != null) {
                out.write(" Using DTD '" + dtd.toString() + "',\r\n");
            } else {
                out.write(" Using DTDs referenced by SYSTEM attribute in each VEO,\r\n");
            }
            if (tempDir != null) {
                out.write(" Extracting to " + tempDir.toString() + ",\r\n");
            }
            if (verbose) {
                out.write(" Verbose output,\r\n");
            }
            if (debug) {
                out.write(" Debug output,\r\n");
            }
            if (results != null) {
                out.write(" Produce summary report\r\n");
            }
            out.write("\r\n");
        } catch (IOException ioe) {
            throw new VEOFatal("Failed trying to write to output: " + ioe.getMessage());
        }
    }

    /**
     * Constructor for headless mode.
     *
     * @param dtd the dtd to use to validate the document (null if no
     * validation)
     * @param logLevel logging level (INFO = verbose, FINE = debug)
     * @param ltsfs long term sustainable formats
     * @param migration true if migrating from old DSA - back off on some of the
     * validation
     * @param results if not null, summarise error messages here
     */
    public VEOCheck(Path dtd, Level logLevel, LTSF ltsfs, boolean migration, ResultSummary results) {

        // default logging
        LOG.getParent().setLevel(logLevel);
        LOG.setLevel(null);

        // set globals
        headless = true;
        testSignatures = true;
        testValues = !migration;
        version1 = false;
        version2 = true;
        if (logLevel == Level.FINEST) {
            verbose = true;
            debug = true;
        } else if (logLevel == Level.FINE) {
            verbose = true;
            debug = false;
        } else {
            verbose = false;
            debug = false;
        }
        oneLayer = false;
        strict = false;
        da = false;
        extract = false;
        virusCheck = false;
        mcafee = false;
        delay = 1;
        parseVEO = false;
        useStdDtd = false;
        this.dtd = dtd;
        files = new ArrayList<>();
        outputFile = null;
        tempDir = Paths.get(".");
        this.ltsfs = ltsfs;
        out = new StringWriter();
        this.results = results;
        help = false;
        forceProgressReport = false;

        // set up standard tests...
        parse = new ParseVEO(verbose, da, strict, oneLayer, out, results);
        valueTester = new TestValues(verbose, strict, da, oneLayer, this.ltsfs, migration, out, results);
        virusTester = new TestViruses(verbose, strict, da, oneLayer, out, results);
        signatureTester = new TestSignatures(verbose, debug, strict, da, oneLayer, out, results);
    }

    /**
     * Parse command line arguments.
     *
     * Read the command line looking for commands
     * <ul>
     * <li>-all perform all tests
     * <li>-extract extract content from VEO
     * <li>-virus extract content from VEO and check for viruses
     * <li>-d &lt;int&gt; delay before checking for virus removal
     * <li>-eicar use a generic virus test instead of McAfee
     * <li>-strict perform tests according to the standard
     * <li>-da tests customised to what the digital archive will accept
     * <li>-parseVEO don't delete the edited metadata after the run
     * <li>-useStdDtd use DTD from VERS web site
     * <li>-signatures perform tests on signatures
     * <li>-values perform tests on values
     * <li>-f formatFile read the long term sustainable formats from formatFile
     * <li>-out &lt;file&gt; write test results to file
     * <li>-v1.2 force tests for version 1
     * <li>-v2 force tests for version 2
     * <li>-verbose verbose output
     * <li>-oneLayer test only the outer layer
     * <li>-debug output debug information
     * <li>-sr produce summary report of all errors
     * <li>-forceStatus if output is being sent to a file, this allows the status
     * to be written on the console as well
     * </ul>
     * Any argument that does not begin with a '-' character is assumed to be
     * the name of a VEO to check
     * <p>
     * Virus checking is performed by attempting to write the documents to disc.
     * Modern virus checkers will scan files as they are being staged within the
     * operating system to disc. VEOCheck therefore attempts to write a document
     * to disc and then checks to see if it exists. If the file exists it
     * assumes that the file was not infected. To guard against false negatives
     * (where the file is actually infected, but VEOCheck decides it is not, the
     * following strategies are taken:
     * <ul>
     * <li>Check that the virus checking is actually running. By default, this
     * check is performed by testing if the mcshield service is running. This is
     * the default virus checking software on the PROV computers. Otherwise, if
     * the '-eicar' flag is set, EICAR files are generated and checked that they
     * are removed (you should also see a virus warning message). An EICAR file
     * is a standard file that will be detected and handled as if it was a virus
     * by a virus checking software (it is not, though, a virus). Use of the
     * -eicar option may generate warning logs.
     * <li>A delay is enforced before the existence check is performed. When a
     * file is written to disc it is first created in the directory, then
     * content is written. If it is virus infected, the file will be created but
     * no content will be written and the file will be removed. The delay should
     * be set high enough so that the EICAR file is detected as a virus. (The
     * default is 1 second).
     * </ul>
     *
     * @param args
     * @throws VERSCommon.VEOFatal
     */
    final public void parseCommandArgs(String args[]) throws VEOFatal {
        int i;
        String usage = "VEOCheck [-all] [-signatures] [-values] [-virus] [-extract] -f LTSFFile -dtd <dtdFile> [-sr] [-strict] [-da] [-parseVEO] [-oneLayer] [-v1.2|-v2] [-verbose] [-debug] [-out <file>] [-t <tempDir>] <files>+";

        // not in headless mode...
        headless = false;

        // must have at least one command argument...
        if (args.length == 0) {
            throw new VEOFatal("No arguments. Usage: " + usage);
        }

        // go through list of command arguments
        for (i = 0; i < args.length; i++) {
            switch (args[i].toLowerCase()) {
                case "-help": // print help about the command line args
                    help = true;
                    break;
                case "-all": // perform all tests
                    testValues = true;
                    virusCheck = true;
                    extract = true; // need to extract to test for viruses
                    testSignatures = true;
                    break;
                case "-strict": // test strictly according to the standard
                    strict = true;
                    break;
                case "-da": // test according to what the da will accept
                    da = true;
                    break;
                case "-extract": // extract content and leave it in files
                    extract = true;
                    break;
                case "-virus": // extract content and virus check it
                    extract = true;
                    virusCheck = true;
                    mcafee = false;
                    break;
                case "-d": // delay for virus checking
                    i++;
                    if (i == args.length) {
                        throw new VEOFatal("Missing integer after '-d'\nUsage: " + usage);
                    }
                    delay = Integer.parseInt(args[i]);
                    break;
                case "-f": // specify a format file
                    i++;
                    if (i == args.length) {
                        throw new VEOFatal("Missing format file after '-f'\nUsage: " + usage);
                    }
                    try {
                        ltsfs = new LTSF(Paths.get(args[i]));
                    } catch (VEOError ve) {
                        throw new VEOFatal("Could not parse format file '" + args[i] + "' due to: " + ve.getMessage());
                    }
                    break;
                case "-eicar": // use the EICAR testing method rather than seeing if the mcshield software is running
                    extract = true;
                    virusCheck = true;
                    mcafee = false;
                    break;
                case "-parseveo": // don't delete the edited metadata after run
                    parseVEO = true;
                    break;
                case "-usestddtd": // use the standard DTD from the web site
                    if (dtd == null) {
                        useStdDtd = true;
                    } else {
                        throw new VEOFatal("Cannot use '-dtd' and '-usestddtd' together");
                    }
                    break;
                case "-dtd": // specify output file
                    i++;
                    if (i == args.length) {
                        throw new VEOFatal("Missing dtd file after '-dtd'\nUsage: " + usage);
                    }
                    dtd = Paths.get(args[i]);
                    if (useStdDtd) {
                        throw new VEOFatal("Cannot use '-dtd' and '-usestddtd' together");
                    }
                    break;
                case "-signatures": // test signatures in VEO
                    testSignatures = true;
                    break;
                case "-values": // test values in VEO
                    testValues = true;
                    break;
                case "-sr":
                    results = new ResultSummary();
                    break;
                case "-v1.2": // force version 1.2 or 2.0 processing
                    version1 = true;
                    version2 = false;
                    break;
                case "-v2":
                    version1 = false;
                    version2 = true;
                    break;
                case "-onelayer": // test only the outer layer
                    oneLayer = true;
                    break;
                case "-verbose": // verbose output
                    verbose = true;
                    break;
                case "-debug": // debug output
                    debug = true;
                    break;
                case "-out": // specify output file
                    i++;
                    if (i == args.length) {
                        throw new VEOFatal("Missing output file after '-out'\nUsage: " + usage);
                    }
                    outputFile = Paths.get(args[i]);
                    break;
                case "-t": // specify a directory in which to put the extracted content
                    i++;
                    if (i == args.length) {
                        throw new VEOFatal("Missing temporary directory after '-t'\nUsage: " + usage);
                    }
                    tempDir = Paths.get(args[i]);
                    break;
                case "-forcestatus":
                    forceProgressReport = true;
                    break;
                default: // anything not starting with a '-' is a VEO
                    if (args[i].charAt(0) == '-') {
                        throw new VEOFatal("Unknown argument: '" + args[i] + "\nUsage: " + usage);
                    } else {
                        try {
                            files.add(Paths.get(args[i]));
                        } catch (InvalidPathException ipe) {
                            throw new VEOFatal("Invalid file name for VEO: " + ipe.getMessage());
                        }
                    }
                    break;
            }
        }

        // sanity check
        if (ltsfs == null) {
            throw new VEOFatal("No LTSF file specified.\nUsage: " + usage);
        }
    }

    /**
     * Test the VEOs when run from the command line
     *
     * Go through the list of files on the command line and run the tests on
     * each VEO. Print the results.
     *
     * @throws VEOError if something failed
     * @throws java.io.IOException
     */
    public void testVEOs() throws VEOError, IOException {
        int i;
        Path veo;

        if (headless) {
            return;
        }

        // set up standard tests...
        parse = new ParseVEO(verbose, da, strict, oneLayer, out, results);
        valueTester = new TestValues(verbose, strict, da, oneLayer, this.ltsfs, false, out, results);
        virusTester = new TestViruses(verbose, strict, da, oneLayer, out, results);
        signatureTester = new TestSignatures(verbose, false, strict, da, oneLayer, out, results);

        // if a temporary directory is specified, open it (create if necessary)
        if (tempDir != null) {
            if (!Files.exists(tempDir)) {
                try {
                    Files.createDirectory(tempDir);
                } catch (IOException e) {
                    throw new VEOError("Failed creating temporary directory: " + e);
                }
            } else if (!Files.isDirectory(tempDir)) {
                throw new VEOError("Temporary directory " + tempDir.toString() + " already exists but is not a directory");
            }
        } else {
            tempDir = Paths.get(".");
        }

        // check that the virus checking software is running
        checkVirusScannerRunning(tempDir, false);

        // go through the list of VEOs
        for (i = 0; i < files.size(); i++) {
            veo = files.get(i);
            if (veo == null) {
                continue;
            }

            // if veo is a directory, go through directory and test all the VEOs
            // otherwise just test the VEO
            check(veo);
        }

        // check that the virus checking software is STILL running
        checkVirusScannerRunning(tempDir, true);
    }

    /**
     * Print a summary of the results on the Writer out.
     *
     * @throws IOException
     */
    public void produceSummaryReport() throws IOException {
        if (headless || results == null || out == null) {
            return;
        }
        results.report(out);
    }

    /**
     * Recurse checking files
     */
    private void check(Path file) throws VEOError {
        DirectoryStream<Path> ds;
        String filePath;

        try {
            filePath = file.toFile().getCanonicalPath();
        } catch (IOException ioe) {
            throw new VEOError("Failed to identify file/directory '" + file.toString() + "' because: " + ioe.getMessage());
        }

        if (!Files.exists(file)) {
            System.out.println("Failed to process file '" + filePath + "': it does not exist");
            return;
        }

        if (Files.isDirectory(file)) {
            try {
                ds = Files.newDirectoryStream(file);
                for (Path p : ds) {
                    check(p);
                }
                ds.close();
            } catch (IOException e) {
                System.out.println("Failed to process directory '" + filePath + "': " + e.getMessage());
            }
        } else if (Files.isRegularFile(file)) {
            try {
                out.write("******************************************************************************\r\n");
                if (!file.toString().toLowerCase().endsWith(".veo")) {
                    out.write("Ignored '" + filePath + "': as it does not end in '.veo'\r\n");
                } else {
                    try {
                        checkVEO(filePath);
                    } catch (IOException e) {
                        System.out.println("Failed to process file '" + filePath + "': " + e.getMessage());
                    }
                }
                out.flush();
            } catch (IOException e) {
                System.out.println("Failed in complaining that file '" + filePath + "' was not a VEO: " + e.getMessage() + "\r\n");
            }
        }
    }

    /**
     * Do the tests when running from the command line. The method vpaTestVEO()
     * is used when running through the API.
     *
     * Passed the file that contains the VEO
     */
    private boolean checkVEO(String filename) throws VEOError, IOException {
        org.w3c.dom.Element vdom;
        boolean overallResult;
        PullApartVEO pav;
        ArrayList<String> content;
        Path p, p1;
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");

        if (headless) {
            return (false);
        }
        
        // if reporting is going into a file, also write it to the console
        // so that users have some sense of what is going on
        if (outputFile != null || forceProgressReport) {
            System.err.println(sdf.format(new Date())+" "+filename);
        }

        overallResult = true;
        content = null;

        out.write("New test. Testing '" + filename + "'\r\n");
        p = Paths.get(filename);
        if (!Files.exists(p)) {
            out.write("  FAILED: VEO does not exist\r\n");
            return false;
        }
        if (!Files.isReadable(p)) {
            out.write("  FAILED: cannot read VEO\r\n");
            return false;
        }

        // first extract the contents of the document data to reduce processing
        if (!parseVEO) {
            pav = new PullApartVEO(dtd);
            p1 = null;
            try {
                p1 = Files.createTempFile(Paths.get("."), "Content", ".eveo");
                content = pav.extractDocumentData(p, p1, tempDir, useStdDtd, extract, virusCheck);
            } catch (VEOError | IOException e) {
                if (p1 != null) {
                    Files.delete(p1);
                }
                out.write("FAILURE: " + e.getMessage() + " (VEOCheck.checkVEO() PullApartVEO)\r\n");
                return false;
            }
        } else {
            p1 = p;
        }

        // first parse the file; if it fails return and stop this test
        if (!parse.performTest(filename, p1.toFile(), dtd, useStdDtd)) {
            if (!parseVEO) {
                Files.delete(p1);
            }
            return false;
        }
        vdom = parse.getDOMRepresentation();

        // perform remaining list of tests...
        if (testValues) {
            if (version1) {
                valueTester.setContext("1.2");
            } else if (version2) {
                valueTester.setContext("2.0");
            }
            overallResult &= valueTester.performTest(filename, vdom);
        } else {
            out.write("Not testing values\r\n");
        }
        if (virusCheck) {
            overallResult &= virusTester.performTest(filename, content, delay);
        } else {
            out.write("Not testing for viruses\r\n");
        }
        if (testSignatures) {
            overallResult &= signatureTester.performTest(filename, p.toFile());
        } else {
            out.write("Not testing signatures\r\n");
        }

        // delete expurgated file
        if (!parseVEO) {
            try {
                Files.delete(p1);
            } catch (IOException ioe) {
                throw new VEOError("Failed deleting: " + ioe.getMessage());
            }
        }
        return overallResult;
    }

    /**
     * Close output file
     */
    public void closeOutputFile() {
        if (headless) {
            return;
        }
        try {
            out.flush(); // shouldn't be necessary, but...
            out.close();
        } catch (IOException e) {
            System.err.println("Closing out writer: " + e.getMessage() + " VEOCheck.closeOutputFile()");
        }
    }

    /**
     * Check that the virus scanner is running. Two methods are used. The
     * default is to attempt to write the EICAR file. If this appears in the
     * output directory, either the virus checking software is not running, or
     * is not checking files for viruses as they are written.
     *
     * @param dir directory in which to create the EICAR file
     * @param endOfRun true if checking for the second time at the end of the
     * run
     * @return true if check for virus scanner succeeded
     * @throws VEOError if virus checking failed, IOException if failed to write
     */
    private boolean checkVirusScannerRunning(Path dir, boolean endOfRun) throws VEOError, IOException {
        int i;

        // only perform this check if checking for viruses
        if (!virusCheck) {
            return true;
        }

        // test virus scanner is running
        try {
            if (mcafee) {
                testMcAfee();
            } else {
                generateEICAR(dir, "eicarStart.txt");
            }
        } catch (VEOError | IOException e) {
            throw new VEOError("VIRUS CHECKING FAILED: Content not checked for viruses as " + e.getMessage() + "\n");
        }

        // record the fact that the check was made
        if (!endOfRun) {
            out.write("Virus scanner is operational. Confirm that it is still operational at end of run.\n");
        } else {
            for (i = 0; i < 79; i++) {
                out.write('*');
            }
            out.write("\r\n");
            out.write("Virus scanner is still operational at end of run. Virus checks are valid.\n");
        }
        return true;
    }

    /**
     * Test to see if this computer has McAfee installed and the server is
     * running. The approach taken is by attempting to start the McAfee mcshield
     * service, and checking to see if the response is that it is actually
     * running. Advice from McAfee is that if the service is running it will
     * detect infected documents as they are written to disk.
     *
     * @return true if the test succeeded
     * @throws IOException
     */
    static final String EXE = "mcshield.exe";
    static final String CMD = "tasklist /fi \"imagename eq " + EXE + "\" /nh";

    private void testMcAfee() throws IOException, VEOError {
        int res;
        Runtime rt;
        Process proc;
        InputStream stderr, output;
        InputStreamReader isr;
        BufferedReader br;
        String line;
        boolean mcAfeeRunning;

        res = -1;
        mcAfeeRunning = false;

        // attempt to start the mcshield service 
        rt = Runtime.getRuntime();
        try {
            proc = rt.exec(CMD);
        } catch (IOException e) {
            throw new VEOError("Couldn't execute command to confirm McAfee is running (" + CMD + "): " + e.toString());
        }

        // drain the standard out looking for the specified process 
        output = proc.getInputStream();
        isr = new InputStreamReader(output);
        br = new BufferedReader(isr);
        while ((line = br.readLine()) != null) {
            // System.out.println("lo:" + line); 
            if (line.contains(EXE)) {
                mcAfeeRunning = true;
            }
        }
        try {
            br.close();
            isr.close();
        } catch (IOException e) {
            /* ignore */ }

        // drain stderr of the underlying process to prevent blocking 
        stderr = proc.getErrorStream();
        isr = new InputStreamReader(stderr);
        br = new BufferedReader(isr);
        while ((line = br.readLine()) != null) {
            // System.out.println("le:" + line); 
        }
        try {
            br.close();
            isr.close();
        } catch (IOException e) {
            /* ignore */ }

        // wait for process to terminate
        try {
            res = proc.waitFor();
        } catch (InterruptedException e) {
            throw new VEOError("Checking McAfee service was interupted (" + CMD + "): " + e.toString());
        }
        // out.write("Exec: '" + CMD + "' returned: " + res + " McAfee Running: " + mcAfeeRunning + "\n"); 
        if (!mcAfeeRunning) {
            throw new VEOError("McAfee virus scanner is NOT running. Returned: " + res + "\n");
        }
    }

    /**
     * Generate a file containing the EICAR content. This content will be (or
     * should be) detected by a virus scanner as a virus and handled.
     *
     * @param dir directory in which to create the EICAR file
     * @param file name to create
     * @throws VEOError if a failure occurred when creating the EICAR file
     */
    private void generateEICAR(Path dir, String file) throws VEOError {
        Path eicar;
        FileOutputStream fos;
        OutputStreamWriter osw;

        // test for eicar.txt file and remove if present
        eicar = Paths.get(dir.toString(), file);
        if (Files.exists(eicar)) {
            try {
                Files.delete(eicar);
            } catch (IOException ioe) {
                throw new VEOError("Failed to delete '" + eicar.toString() + "':" + ioe.toString());
            }
        }

        // try to create eicar.txt file
        try {
            fos = new FileOutputStream(eicar.toFile());
        } catch (FileNotFoundException e) {
            throw new VEOError("Failed to create '" + eicar.toString() + "': " + e.toString());
        }
        osw = new OutputStreamWriter(fos);
        try {
            osw.write("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
        } catch (IOException e) {
            throw new VEOError("Failed in writing to '" + eicar.toString() + "': " + e.toString());
        }
        try {
            osw.close();
        } catch (IOException e) {
            throw new VEOError("Failed in closing osw in '" + eicar.toString() + "': " + e.toString());
        }
        try {
            fos.close();
        } catch (IOException e) {
            throw new VEOError("Failed in closing fos in '" + eicar.toString() + "': " + e.toString());
        }

        // delay to give virus checker time to work
        try {
            TimeUnit.SECONDS.sleep(delay);
        } catch (InterruptedException e) {
            /* ignore */
        }

        // check that virus checker removed first EICAR file
        if (Files.exists(eicar)) {
            throw new VEOError("Virus checker did not remove '" + eicar.toString() + "'. Virus checking is consequently not effective. This indicates virus checker is either not running or not detecting creation of virus infected files");
        }
    }

    /**
     * Test a single VEO in headless mode
     *
     * @param veo the original VEO including document content
     * @param cutVEO cut down VEO with document content removed
     * @param out a StringWriter to capture output
     * @return true if test was successful
     * @throws VEOError
     */
    public boolean vpaTestVEO(Path veo, Path cutVEO, StringWriter out) throws VEOError {
        org.w3c.dom.Element vdom;
        boolean overallResult;

        if (!headless) {
            return false;
        }
        tempDir = Paths.get("."); // temporary directory
        overallResult = true;
        parse.setOutput(out);
        valueTester.setOutput(out);
        virusTester.setOutput(out);
        signatureTester.setOutput(out);

        if (!Files.exists(veo)) {
            throw new VEOError("  FAILED: VEO does not exist\r\n");
        }
        if (!Files.isReadable(veo)) {
            throw new VEOError("  FAILED: cannot read VEO\r\n");
        }

        // first parse the file; if it fails return and stop this test
        if (!parse.performTest(veo.toString(), cutVEO.toFile(), dtd, useStdDtd)) {
            return false;
        }
        vdom = parse.getDOMRepresentation();

        // perform remaining list of tests...
        if (testValues) {
            if (version1) {
                valueTester.setContext("1.2");
            } else if (version2) {
                valueTester.setContext("2.0");
            }
            overallResult &= valueTester.performTest(veo.toString(), vdom);
        }
        /*
        if (virusCheck) {
            overallResult &= virusTester.performTest(content, delay);
        }
         */
        if (testSignatures) {
            overallResult &= signatureTester.performTest(veo.toString(), veo.toFile());
        }
        return overallResult;
    }

    /**
     * Main program.
     *
     * @param args command line arguments
     */
    public static void main(String args[]) {
        VEOCheck vc;

        vc = null;
        try {
            vc = new VEOCheck(args);
            vc.testVEOs();
            vc.produceSummaryReport();
        } catch (IOException | VEOError e) {
            System.err.println(e.getMessage());
            System.exit(-1);
        } finally {
            if (vc != null) {
                vc.closeOutputFile();
            }
        }
    }
}
