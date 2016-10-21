package CVEChecker;

import SourceParser.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.safety.Cleaner;
import org.jsoup.safety.Whitelist;
import org.jsoup.select.Elements;
import org.jsoup.parser.Parser;
import org.antlr.v4.runtime.*;
import org.antlr.v4.runtime.tree.ParseTree;
import org.apache.commons.cli.*;
import java.io.*;
import java.util.*;
import static java.lang.Integer.parseInt;

public class Main {

    private static List<String> patchLinks = null;
    private static List<String> abLinks = new ArrayList<>();
    private static List<String> abFiles = new ArrayList<>();
    private static HashMap<String, ArrayList> fileMapA = new HashMap<String, ArrayList>();
    private static HashMap<String, ArrayList> fileMapB = new HashMap<String, ArrayList>();
    private static boolean showAll = false;
    private static boolean showFunc =  false;
    private static boolean showJava = false;
//    private static HashSet<String> aFuncs = new HashSet<>();
//    private static HashSet<String> bFuncs = new HashSet<>();
    private static HashSet<String> funcs = new HashSet<>();
    private static int round = 1;

    public static void main(String[] args) throws IOException {
        Options options = new Options();

        Option cveId = new Option("i", "cveId", true, "CVE ID");
        //cveId.setRequired(true);
        options.addOption(cveId);
        Option patchLink = new Option("p", "patchLink", true, "Patch url address");
        //patchLink.setRequired(true);
        options.addOption(patchLink);
        options.addOption("a", "showAll", false, "Display all information");
        options.addOption("f", "showFunc", false, "Display updated functions");
        options.addOption("j", "showJava", false, "Display java patch info");

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("CVEChecker", options);
            System.exit(1);
            return;
        }

        String cveIdNumber = cmd.getOptionValue("cveId");
        String patchLinkString = cmd.getOptionValue("patchLink");
        showAll = cmd.hasOption("a");
        showFunc = cmd.hasOption("f");
        showJava = cmd.hasOption("j");

        if (cveIdNumber != null) {
            getPatchLinks(cveIdNumber);

            for (String link : patchLinks) {
                processPatchLink(link, round);
                round++;
                if (showAll)
                    System.out.println();
            }

            if (patchLinks.size() == 0) {
                if (showAll)
                    System.out.println("Couldn't locate patch links");
            }
        } else if (patchLinkString != null) {
            processPatchLink(patchLinkString, 1);
        } else {
            formatter.printHelp("CVEChecker", options);
        }

        if (showFunc) {
            for (String func : funcs) {
                System.out.printf("-%s\n", func);
            }
        }

        return;
    }

    private static void getPatchLinks(String cveNum) throws IOException {
        String cveUrl[] =  {"https://cve.mitre.org/cgi-bin/cvename.cgi?name=",
                            "https://web.nvd.nist.gov/view/vuln/detail?vulnId=",
                            "http://www.cvedetails.com/cve/"};

        for (String urlPrefix : cveUrl) {
            String url = urlPrefix + cveNum;

            Document doc = Jsoup.connect(url).get();
            Elements links = doc.select("a[href]");
            patchLinks = new ArrayList<>();

            for (Element link : links) {
                boolean confirmedLink = link.text().contains("https://android.googlesource.com");
                if (confirmedLink == true) {
                    //processDiffLink(link);
                    patchLinks.add(link.attr("abs:href"));
                }
            }
            if (patchLinks.size() > 0) break;
        }
        //String cveUrl = "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-2461
        //http://www.cvedetails.com/cve/CVE-2016-2461/
        //https://cve.mitre.org/cgi-bin/cvename.cgi?name=
    }

    private static void processPatchLink(String link, int round) throws IOException {
        ArrayList<Integer> aRanges;
        ArrayList<Integer> bRanges;
        Document pdoc = Jsoup.connect(link).get();
        Elements plinks = pdoc.select("a[href]");

        Elements diffTree = pdoc.select("ul.DiffTree").select("li");
        List<String> fileList = new ArrayList<String>();
        for (Element li : diffTree) {
            fileList.add(li.select("a").first().text());
        }
        if (showAll) {
            System.out.format("Update %d: %d file(s) changed, patch link: %s\n", round, fileList.size(), link);
        }

        HashSet<String> diffLinks = new HashSet<>();
        for (Element plink : plinks) {
            boolean isDiffLink = plink.text().equals("diff");
            if (isDiffLink == true) {
                diffLinks.add(plink.attr("abs:href").split("#")[0]);
            }
        }
        for (String dlink : diffLinks) {
            processDiffLink(dlink);
        }

        if (fileMapA.size() == fileMapB.size() && abFiles.size() == abLinks.size()) {
            if (showAll)
                System.out.println("Functions affected before patch: ");
            for (int i = 0; i < abFiles.size(); i+=2) {
                if (abFiles.get(i).endsWith(".h")) {
                    //System.out.printf("Header file skipped: %s\n", abFiles.get(i));
                    continue;
                }
                aRanges = fileMapA.get(abFiles.get(i));
                if (showAll)
                    System.out.printf("Update link: %s \n", abLinks.get(i));
                if (!abLinks.get(i+1).equals("/dev/null")) {
                    processSourceFile(abFiles.get(i), abLinks.get(i), aRanges);
                }
            }

            if (showAll)
                System.out.println("Functions affected after patch: ");
            for (int i = 0; i < abFiles.size(); i+=2) {
                if (abFiles.get(i).endsWith(".h")) {
                    //System.out.printf("Header file skipped: %s\n", abFiles.get(i+1));
                    continue;
                }
                bRanges = fileMapB.get(abFiles.get(i+1));
                if (showAll)
                    System.out.printf("Update link: %s \n", abLinks.get(i+1));
                if (!abLinks.get(i+1).equals("/dev/null")) {
                    processSourceFile(abFiles.get(i + 1), abLinks.get(i + 1), bRanges);
                }
            }
        } else {
            if (showAll)
                System.out.printf("Potential parser error: %d\n", link);
        }

        fileMapA.clear();
        fileMapB.clear();
        abFiles.clear();
        abLinks.clear();
    }

    private static void processDiffLink(String dlink) throws IOException {
        ArrayList<Integer> aRanges = new ArrayList<>();
        ArrayList<Integer> bRanges = new ArrayList<>();
        List<String> lineNums;
        String line;
        String currentFile = null;

        Document diffDoc = Jsoup.connect(dlink).get();
        diffDoc = new Cleaner(Whitelist.basic()).clean(diffDoc);
        Scanner scanner = new Scanner(diffDoc.body().select("pre").html());

        while (scanner.hasNextLine()) {
            line = Parser.unescapeEntities(scanner.nextLine(), false);

            if (line.contains("diff --git")) {
                int count = 0;
                String temp = "";
                Document tdoc = Jsoup.parseBodyFragment(line);
                for (Element a : tdoc.select("a[href]")) {
                    temp = a.attr("abs:href");
                    currentFile = temp.split("/+/")[1];
                    currentFile = currentFile.substring(currentFile.indexOf("/")+1);
                    abLinks.add(temp);
                    count++;
                }
                if (count != 2) abLinks.add("/dev/null");
            }
            if (line.startsWith("---")) {
                fileMapA.put(currentFile, aRanges);
                aRanges = new ArrayList<>();
                abFiles.add(currentFile);
            }
            if (line.startsWith("+++")) {
                fileMapB.put(currentFile, bRanges);
                bRanges = new ArrayList<>();
                abFiles.add(currentFile);
            }
            if (line.startsWith("<span>@@") && line.endsWith("@@")) {
                line = line.replaceAll("[^0-9]+", " ").trim();
                lineNums = Arrays.asList(line.split(" "));
                if (lineNums.size() == 4) {
                    aRanges.add(parseInt(lineNums.get(0)) + 3);
                    aRanges.add(parseInt(lineNums.get(0)) + parseInt(lineNums.get(1)) - 3);
                    bRanges.add(parseInt(lineNums.get(2)) + 3);
                    bRanges.add(parseInt(lineNums.get(2)) + parseInt(lineNums.get(3)) - 3);
                }
            }
        }
        fileMapA.put(currentFile, aRanges);
        fileMapB.put(currentFile, bRanges);

        scanner.close();
    }

    private static void processSourceFile(String fName, String fLink, ArrayList<Integer> ranges) throws IOException {
        List<Pair<Integer, Integer>> rangeList = new ArrayList<>();
        Integer m, n;

        for (int i=0; i<ranges.size(); i+=2) {
            m = ranges.get(i);
            n = ranges.get(i+1);
            rangeList.add(new Pair(m, n));
        }

        if (rangeList.size() > 0) {
            Document sourceCode = Jsoup.connect(fLink + "/?format=TEXT").get();
            byte[] base64Str = Base64.getDecoder().decode(sourceCode.text());

            if (fName.endsWith(".c")) {
                // Hack for c source code preprocessing
                byte[] filterBase64Str = filter(base64Str);
                InputStream inputStream = new ByteArrayInputStream(filterBase64Str);
                ANTLRInputStream antlrInputStream = new ANTLRInputStream(inputStream);
                CLexer cLexer = new CLexer(antlrInputStream);
                cLexer.removeErrorListeners();
                CommonTokenStream tokenStream = new CommonTokenStream(cLexer);
                CParser cParser = new CParser(tokenStream);
                cParser.removeErrorListeners();
                ParseTree parseTree = cParser.compilationUnit();

                CMethodVisitor cMethodVisitor = new CMethodVisitor();
                cMethodVisitor.setRanges(fName, rangeList);
                cMethodVisitor.visit(parseTree);
            } else if (fName.endsWith(".cpp") || fName.endsWith(".cc")) {
                byte[] filterBase64Str = filter(base64Str);
                InputStream inputStream = new ByteArrayInputStream(filterBase64Str);
                ANTLRInputStream antlrInputStream = new ANTLRInputStream(inputStream);

                CPP14Lexer cpp14Lexer = new CPP14Lexer(antlrInputStream);
                cpp14Lexer.removeErrorListeners();
                CommonTokenStream tokenStream = new CommonTokenStream(cpp14Lexer);
                CPP14Parser cpp14Parser = new CPP14Parser(tokenStream);
                cpp14Parser.removeErrorListeners();
                ParseTree parseTree = cpp14Parser.translationunit();

                CPPMethodVisitor cppMethodVisitor = new CPPMethodVisitor();
                cppMethodVisitor.setRanges(fName, rangeList);
                cppMethodVisitor.visit(parseTree);
//                ParseTreeWalker walker = new ParseTreeWalker();
//                CPP14Listerner cpp14Listerner = new CPP14Listerner(cpp14Parser);
//                walker.walk(cpp14Listerner, parseTree);
            } else if (showJava && fName.endsWith(".java")) {
                InputStream inputStream = new ByteArrayInputStream(base64Str);
                ANTLRInputStream antlrInputStream = new ANTLRInputStream(inputStream);

                Java8Lexer java8Lexer = new Java8Lexer(antlrInputStream);
                CommonTokenStream tokenStream = new CommonTokenStream(java8Lexer);
                Java8Parser java8Parser = new Java8Parser(tokenStream);
                ParseTree parseTree = java8Parser.compilationUnit();

                JavaMethodVisitor javaMethodVisitor = new JavaMethodVisitor();
                javaMethodVisitor.setRanges(fName, rangeList);
                javaMethodVisitor.visit(parseTree);
            }
        }
    }

    private static byte[] filter(byte[] input) {
        StringBuilder sb = new StringBuilder();
        String line = "", tempLine = "";
        boolean multiline = false;
        String temp = "";

        Scanner scanner = new Scanner(new String(input));

        while (scanner.hasNextLine()) {
            line = scanner.nextLine();
            if (line.endsWith("\\")) {
                tempLine += line.replace("\\", "");
                temp += "\r\n";
                multiline = true;
            } else {
                if (multiline == true && temp != "") {
                    tempLine += line;
                    temp += "\r\n";
                    if (!tempLine.startsWith("#")) {
                        sb.append(tempLine);
                    }
                    sb.append(temp);
                    tempLine = "";
                    temp = "";
                    multiline = false;
                } else {
                    if (!line.startsWith("#")) {
                        sb.append(line + "\r\n");
                    } else {
                        sb.append("\r\n");
                    }
                }
            }
        }

//        scanner = new Scanner(sb.toString());
//        sb.setLength(0);
//        while (scanner.hasNextLine()) {
//            line = scanner.nextLine();
//            if (line.endsWith(",")) {
//                sb.append(line);
//                temp += "\r\n";
//                commaline = true;
//            } else {
//                if (line != "") {
//                    sb.append(line + "\r\n");
//                    if (commaline == true && temp != "") {
//                        sb.append(temp);
//                        temp = "";
//                        commaline = false;
//                    }
//                } else {
//                    temp += "\r\n";
//                }
//            }
//        }

//        int i = 1;
//        scanner = new Scanner(sb.toString());
//        while (scanner.hasNextLine()) {
//            System.out.printf("%d: %s\n", i, scanner.nextLine());
//            i++;
//        }

        return sb.toString().getBytes();
    }

    private static boolean pairCompare(Pair<Integer, Integer> source, Pair<Integer, Integer> target) {
        if (source.getLeft() <= target.getLeft() && source.getRight() >= target.getRight()) {
            return true;
        } else if (source.getLeft() >= target.getLeft() && source.getRight() <= target.getLeft()) {
            return true;
        } else if (source.getRight() >= target.getLeft() && source.getRight() <= target.getRight()) {
            return true;
        } else {
            return false;
        }
    }

    static class JavaMethodVisitor extends Java8BaseVisitor<Void> {

        private String currentFileName = null;
        private List<Pair<Integer, Integer>> ranges = null;
        private Integer start, end;

        public void setRanges(String funcName, List<Pair<Integer, Integer>> ranges) {
            this.currentFileName = funcName;
            this.ranges = ranges;
        }

        @Override
        public Void visitMethodDeclaration(Java8Parser.MethodDeclarationContext ctx) {
            String currentFuncName = ctx.methodHeader().methodDeclarator().Identifier().getText();

            start = ctx.getStart().getLine();
            end = ctx.getStop().getLine();

            for (Pair<Integer, Integer> pair : this.ranges) {
                if (pairCompare(new Pair<Integer, Integer>(start, end), pair)) {
                    if (showAll) {
                        System.out.printf("Update func: %s, %s\n", currentFileName, currentFuncName);
                    }
                    if (showFunc) {
                        funcs.add(currentFuncName);
                    }
                }
            }

            return null;
        }
    }

    static class CMethodVisitor extends CBaseVisitor<Void> {

        private String currentFileName = null;
        private List<Pair<Integer, Integer>> ranges = null;
        private Integer start, end;

        public void setRanges(String funcName, List<Pair<Integer, Integer>> ranges) {
            this.currentFileName = funcName;
            this.ranges = ranges;
        }

        @Override
        public Void visitFunctionDefinition(CParser.FunctionDefinitionContext ctx) {
            String currentFuncName = ctx.declarator().directDeclarator().getText();

            start = ctx.getStart().getLine();
            end = ctx.getStop().getLine();

            for (Pair<Integer, Integer> pair : this.ranges) {
                if (pairCompare(new Pair<Integer, Integer>(start, end), pair)) {
                    if (showAll) {
                        System.out.printf("Update func: %s, %s\n", currentFileName, currentFuncName);
                    }
                    if (showFunc) {
                        // C code, only keep the func name
                        funcs.add(currentFuncName.split("\\(")[0]);
                    }
                }
            }
            return null;
        }
    }


    static class CPPMethodVisitor extends CPP14BaseVisitor<Void> {

        private String currentFileName = null;
        private List<Pair<Integer, Integer>> ranges = null;
        private Integer start, end;

        public void setRanges(String funcName, List<Pair<Integer, Integer>> ranges) {
            this.currentFileName = funcName;
            this.ranges = ranges;
        }

        @Override
        public Void visitFunctiondefinition(CPP14Parser.FunctiondefinitionContext ctx) {
            String currentFuncName = ctx.declarator().getText();
//            String currentFuncName = ctx.declarator().noptrdeclarator().getText();

            start = ctx.getStart().getLine();
            end = ctx.getStop().getLine();

            for (Pair<Integer, Integer> pair : this.ranges) {
                if (pairCompare(new Pair<Integer, Integer>(start, end), pair)) {
                    if (showAll) {
                        System.out.printf("Update func: %s, %s\n", currentFileName, currentFuncName);
                    }
                    if (showFunc) {
                        funcs.add(currentFuncName);
                    }
                }
            }

            return null;
        }
    }

    static class Pair<L,R> {

        private final L left;
        private final R right;

        public Pair(L left, R right) {
            this.left = left;
            this.right = right;
        }

        public L getLeft() { return left; }
        public R getRight() { return right; }

        @Override
        public int hashCode() { return left.hashCode() ^ right.hashCode(); }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Pair)) return false;
            Pair pairo = (Pair) o;
            return this.left.equals(pairo.getLeft()) &&
                    this.right.equals(pairo.getRight());
        }
    }
}
