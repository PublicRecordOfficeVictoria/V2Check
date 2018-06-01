/*
 * Copyright Public Record Office Victoria 2018
 * Licensed under the CC-BY license http://creativecommons.org/licenses/by/3.0/au/
 * Author Andrew Waugh
 */

package VEOCheck;

/**
 * *************************************************************
 *
 * T E S T V I R U S E S
 *
 * This class tests the contents of a VEO for virus infection.
 *
 *************************************************************
 */
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class TestViruses extends TestSupport {
    private final static Logger LOG = Logger.getLogger("VEOCheck.TestViruses");

    /**
     * Constructor
     *
     * @param verbose
     * @param strict
     * @param da
     * @param oneLayer
     * @param out
     */
    public TestViruses(boolean verbose, boolean strict,
            boolean da, boolean oneLayer, Writer out) {
        super(verbose, strict, da, oneLayer, out);
    }

    /**
     *
     * Return the name of this test
     *
     * @return true if the test succeeded
     */
    @Override
    public String getName() {
        return "TestViruses";
    }

    /**
     * Test if files have been found to be virus infected.
     *
     * @param files list of files to be tested
     * @param delay number of seconds to delay to give the virus checker time to
     * work
     * @return true if the test succeeded
     */
    public boolean performTest(ArrayList<String> files, int delay) {
        String file;
        Path p;
        int i;
        boolean fail;

        startSubTest("TESTING FOR VIRUSES");
        
        // delay to give virus checker time to work
        try {
            TimeUnit.SECONDS.sleep(delay);
        } catch (InterruptedException e) {
            /* ignore */
        }

        // check to see if the extracted files are still in existance
        fail = false;
        for (i = 0; i < files.size(); i++) {
            file = files.get(i);
            p = Paths.get(".", file);
            if (!Files.exists(p)) {
                println("Content file '" + p + "' was removed - probably because it failed a virus check");
                fail = true;
            }
        }

        if (!fail) {
            passed("No viruses found");
        } else {
            failed("");
        }
        return fail;
    }
}
