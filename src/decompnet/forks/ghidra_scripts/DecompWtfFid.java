// decompdecomp: give Ghidra's Function ID the user's own databases (.fidb) before its analysis, so the analysis
// recognises their libraries' functions as it does the runtime's with its own. Run by analyzeHeadless as a
// pre-script; its arguments are the databases' paths. DecompWtfFunctions then writes what it recognised.
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;

import java.io.File;

public class DecompWtfFid extends GhidraScript {
    @Override
    public void run() throws Exception {
        FidFileManager manager = FidFileManager.getInstance();
        for (String path : getScriptArgs()) {
            FidFile added = manager.addUserFidFile(new File(path));
            if (added == null) {
                println("decompdecomp: Function ID didn't take " + path);
            } else {
                added.setActive(true);
            }
        }
    }
}
