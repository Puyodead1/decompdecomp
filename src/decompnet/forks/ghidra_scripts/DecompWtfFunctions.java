// decompdecomp: list every function Ghidra's analysis found in the imported program, one JSON object per line:
// {"entry": 4198400, "end": 4198420, "name": "FUN_00401000", "source": "DEFAULT", "purge": 8,
//  "convention": "__stdcall", "params": 2, "thunk": false}
// end is one past the highest address of the function's body. Run by analyzeHeadless as a post-script; the output
// path is its argument. Each program analysed adds its functions to the file, with its name ("program": the file's
// name), so one run can analyse several (a V.Flash game's firmware and modules).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

public class DecompWtfFunctions extends GhidraScript {
    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0], true), StandardCharsets.UTF_8))) {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            while (it.hasNext() && !monitor.isCancelled()) {
                Function f = it.next();
                if (f.isExternal()) continue;
                long entry = f.getEntryPoint().getOffset();
                long end = f.getBody().getMaxAddress().getOffset() + 1;
                w.println("{\"entry\": " + entry + ", \"end\": " + end + ", \"name\": " + quote(f.getName())
                        + ", \"source\": " + quote(f.getSymbol().getSource().toString())
                        + ", \"purge\": " + f.getStackPurgeSize()
                        + ", \"convention\": " + quote(String.valueOf(f.getCallingConventionName()))
                        + ", \"params\": " + f.getParameterCount()
                        + ", \"thunk\": " + f.isThunk()
                        + ", \"program\": " + quote(currentProgram.getName()) + "}");
            }
        }
    }
}
