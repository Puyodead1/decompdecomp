// decompdecomp: decompile the functions of a whole program at the addresses listed in a file (one hexadecimal entry
// address a line, in the order to do them; "*": all of them) and write one JSON object per line:
// {"entry": 4198400, "c": "...", "thunk": false, "refs": {
//   "FUN_00401020": {"at": 4198432, "kind": "func", "ret": "int", "args": ["int", "char *"]},
//   "DAT_00402034": {"at": 4202548, "kind": "data", "type": "undefined4", "size": 4},
//   "DeleteFileA": {"at": 0, "kind": "import", "ret": "BOOL", "args": ["LPCSTR"]}}}
// refs: every name the C uses for a function it calls or for global data, read from the decompiler's own tokens (so
// it works for code the analysis didn't make a function of), with the types the decompiler gave a call's arguments
// and result there: declared so, the call compiles as the C writes it. Arguments: the output path, the addresses
// file, and the seconds to stop after (0: none). Run by analyzeHeadless as a post-script.
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class DecompWtfDrafts extends GhidraScript {
    private static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c)); else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private static String typeOf(Varnode v) {
        if (v == null) return "void";
        HighVariable h = v.getHigh();
        DataType t = h != null ? h.getDataType() : null;
        return t != null ? t.getDisplayName() : "undefined" + v.getSize();
    }

    /** What the call `op` passes and gets back, as the decompiler typed them there. */
    private static String call(PcodeOp op) {
        StringBuilder b = new StringBuilder(", \"ret\": ").append(quote(op.getOutput() != null ? typeOf(op.getOutput()) : "void"));
        b.append(", \"args\": [");
        for (int i = 1; i < op.getNumInputs(); i++) {
            if (i > 1) b.append(", ");
            b.append(quote(typeOf(op.getInput(i))));
        }
        return b.append("]").toString();
    }

    private boolean isImport(String name) {
        SymbolIterator it = currentProgram.getSymbolTable().getSymbols(name);
        while (it.hasNext()) {
            Symbol s = it.next();
            if (s.isExternal()) return true;
            Function f = getFunctionAt(s.getAddress());
            if (f != null && f.isThunk() && f.getThunkedFunction(true) != null && f.getThunkedFunction(true).isExternal()) return true;
        }
        return false;
    }

    private void walk(ClangNode node, Map<String, String> refs) {
        for (int i = 0; i < node.numChildren(); i++) {
            ClangNode ch = node.Child(i);
            String name = ch.toString();
            if (ch instanceof ClangFuncNameToken && !refs.containsKey(name)) {
                PcodeOp op = ((ClangFuncNameToken) ch).getPcodeOp();
                if (op != null && (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND)) {
                    Varnode target = op.getInput(0);
                    boolean imported = isImport(name);
                    long at = !imported && op.getOpcode() == PcodeOp.CALL && target.isAddress() ? target.getAddress().getOffset() : 0;
                    refs.put(name, "{\"at\": " + at + ", \"kind\": " + quote(imported ? "import" : "func") + call(op) + "}");
                }
            } else if (ch instanceof ClangVariableToken && !refs.containsKey(name)) {
                HighVariable h = ((ClangVariableToken) ch).getHighVariable();
                if (h instanceof HighGlobal) {
                    HighSymbol s = h.getSymbol();
                    Address a = s != null && s.getStorage() != null ? s.getStorage().getMinAddress() : null;
                    if (a != null && a.isMemoryAddress()) {
                        DataType t = h.getDataType();
                        refs.put(name, "{\"at\": " + a.getOffset() + ", \"kind\": \"data\", \"type\": "
                                 + quote(t != null ? t.getDisplayName() : "") + ", \"size\": " + h.getSize() + "}");
                    }
                }
            }
            walk(ch, refs);
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        List<String> wanted = Files.readAllLines(Paths.get(args[1]));
        if (!wanted.isEmpty() && wanted.get(0).trim().equals("*")) {  // every function (a small object)
            wanted = new java.util.ArrayList<>();
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) wanted.add(f.getEntryPoint().toString());
        }
        long stopAt = args.length > 2 && Long.parseLong(args[2]) > 0 ? System.currentTimeMillis() + 1000 * Long.parseLong(args[2]) : Long.MAX_VALUE;
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        try (PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            for (String line : wanted) {
                if (monitor.isCancelled() || System.currentTimeMillis() > stopAt) break;
                line = line.trim();
                if (line.isEmpty()) continue;
                Address at = toAddr(Long.parseLong(line, 16));
                Function f = getFunctionAt(at);
                if (f == null) {  // code the analysis didn't make a function of (the project cut it out by itself)
                    if (getInstructionAt(at) == null) disassemble(at);
                    f = createFunction(at, null);
                }
                if (f == null || f.isExternal()) continue;
                DecompileResults r = ifc.decompileFunction(f, 30, monitor);
                if (r == null || !r.decompileCompleted() || r.getDecompiledFunction() == null) continue;
                Map<String, String> refs = new LinkedHashMap<>();
                if (r.getCCodeMarkup() != null) walk(r.getCCodeMarkup(), refs);
                StringBuilder js = new StringBuilder("{");
                for (Map.Entry<String, String> e : refs.entrySet()) {
                    if (js.length() > 1) js.append(", ");
                    js.append(quote(e.getKey())).append(": ").append(e.getValue());
                }
                w.println("{\"entry\": " + at.getOffset() + ", \"thunk\": " + f.isThunk() + ", \"c\": "
                          + quote(r.getDecompiledFunction().getC()) + ", \"refs\": " + js.append("}") + "}");
                w.flush();
            }
        } finally {
            ifc.dispose();
        }
    }
}
