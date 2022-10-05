package it.unive.secgroup;

import org.apache.commons.lang3.StringUtils;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Transformer {

    private Set<CharType> types;
    private Map<String, Integer> words = new HashMap<>(500000);
    private Map<String, Integer> rules = new HashMap<>(500000);
    private BufferedOutputStream debug;

    // enhancedCopy activates enhanced copy command in hashcat
    // unfortunately, it cannot be used along with OpenCL kernels
    private boolean enhancedCopy = false;
    private static LocalDate MIN_DATE = LocalDate.of(1950, 1, 1);
    private static LocalDate MAX_DATE = LocalDate.of(2050, 12, 31);
    private static DateTimeFormatter[] DATES = new DateTimeFormatter[] {
            DateTimeFormatter.ofPattern("yyyyMMdd"),
            DateTimeFormatter.ofPattern("ddMMyyyy"),
            DateTimeFormatter.ofPattern("MMddyyyy")};
    public Transformer() {
        this.types = new HashSet<>(Arrays.asList(CharType.values())); // manage all types;
    }

    public Transformer(CharType singleType) {
        this.types = new HashSet<>(Arrays.asList(singleType));
    }

    public void finished() {
        if (debug != null) {
            try {
                debug.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    public enum CharType {
        Alpha,
        Numeric,
        Symbol,
        Email  // not a character type actually
    };
    private static final String REPLACEABLE = "0123456789$@(+|!";
    private static final String REPLACED    = "oizeasbtbgsactii";
    public static final Pattern VALID_EMAIL_ADDRESS_REGEX =
            Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);
    public boolean isEmail(String emailStr) {
        Matcher matcher = VALID_EMAIL_ADDRESS_REGEX.matcher(emailStr);
        return matcher.find();
    }
    private boolean isLower(char c) { return c >= 'a' && c <= 'z'; }
    private boolean isUpper(char c) { return c >= 'A' && c <= 'Z'; }
    private boolean isNumber(char c) { return c >= '0' && c <= '9'; }
    private boolean isAlpha(char c) { return isLower(c) || isUpper(c);}
    private boolean isSymbol(char c) { return !isNumber(c) && !isAlpha(c); }

    /* experimental
       not implemented
    private static final String[] FROM_ = {"for", "to", "per", "you",  "2k9",  "2k8",  "2k7",  "2k6",  "2k5",  "2k4",  "2k3",  "2k2",  "2k1",   "2k",   "&",   "4",  "2",   "x",   "u", "2009", "2008", "2007", "2006", "2005", "2004", "2003", "2002", "2001", "2000", "and"};
    private static final String[] SHORTENED   = {"4",    "2",   "x",   "u", "2009", "2008", "2007", "2006", "2005", "2004", "2003", "2002", "2001", "2000", "and", "for", "to", "per", "you",  "2k9",  "2k8",  "2k7",  "2k6",  "2k5",  "2k4",  "2k3",  "2k2",  "2k1",   "2k",   "&"};

    public String manageShortening(String pwd) {
        return "";
    }
     */

    public static void addToMap(String item, Map<String, Integer> items) {
        if (item != null) {
            Integer count = items.get(item);
            if (count == null) count = 0;
            items.put(item, count + 1);
        }
    }

    private CharType detectMainComponent(String pwd) {
        int maxa = 0, maxn = 0, maxs = 0;
		int a = 0, n = 0, s = 0;
		int at = 0, dot = 0, i = 0;

        // first, check for the greatest amount of character type
        // in case of pair, alphabetic content will be preferred
        for (char c : pwd.toCharArray()) {
            if (isAlpha(c)) a++;
            else if (isNumber(c)) n++;
            else {
                if      (c == '@') at = i;
                else if (c == '.') dot = i;
                s++;
            }
            i++;
        }
        if (at > 0 && dot > at && isEmail(pwd)) return CharType.Email;
        if (a >= n + s || a >= n && a >= s)     return CharType.Alpha;
        if (n >= a + s || n >= a && n > s)      return CharType.Numeric;
        if (s == pwd.length())                  return CharType.Symbol;

        // no winner found so far.
        // try to check the character type that presents the longest consecutive sequence
        a = 0; n = 0; s = 0;
        for (char c : pwd.toCharArray()) {
            if (isAlpha(c)) {
                n = 0; s = 0; a++;
            } else if (isNumber(c)) {
                a = 0; s = 0; n++;
            } else {
                a = 0; n = 0; s++;
            }
            if (maxa < a) maxa = a;
            if (maxn < n) maxn = n;
            if (maxs < s) maxs = s;
        }
        if      (maxa >= maxn + maxs || maxa >= maxn && maxa >= maxs - 1) return CharType.Alpha;
        else if (maxn >= maxa + maxs || maxn >= maxa && maxn >= maxs - 1) return CharType.Numeric;

        // no better choices
        return CharType.Symbol;
    }

    private String extractPart(String pwd, CharType charType) {
        // extracts the interested part
        // e.g.: pwd = !!my_name124 , charType = Alpha -> result = myname
        StringBuilder res = new StringBuilder(pwd.length());
        for (char c : pwd.toCharArray()) {
            if (       charType.equals(CharType.Alpha)   && isAlpha(c)
                    || charType.equals(CharType.Numeric) && isNumber(c)
                    || charType.equals(CharType.Symbol)  && isSymbol(c))
                res.append(c);
        }
        return res.toString();
    }

    private String removeWrapper(String l, CharType type) {
        // Note: removeWrapper differs slightly from extractPart. eg:
        // original      : 123ab(_def!!!
        // extract alpha : abdef
        // unwrap alpha  : ab(_def

        int s = 0;
        int e = l.length() - 1;
        while (s <= e && (type.equals(CharType.Alpha)   && !isAlpha(l.charAt(s)))
                       || type.equals(CharType.Numeric) && !isNumber(l.charAt(s))
                       || type.equals(CharType.Symbol)  && !isSymbol(l.charAt(e))) {
            s++;
        }
        while (s <= e && (type.equals(CharType.Alpha)   && !isAlpha(l.charAt(e)))
                       || type.equals(CharType.Numeric) && !isNumber(l.charAt(e))
                       || type.equals(CharType.Symbol)  && !isSymbol(l.charAt(e))) {
            e--;
        }
        String result = l.substring(s, e + 1);
        return result;
    }

    private void addPrefixRule(StringBuilder rule, int s, String pwd) {
        while (s > 0)                {s--; rule.append("^").append(pwd.charAt(s));}
    }

    private void addSuffixRule(StringBuilder rule, int e, String pwd) {
        while (e < pwd.length() - 1) {e++; rule.append("$").append(pwd.charAt(e));}
    }

    private void addInsertRule(StringBuilder rule, int i, String pwd) {
        rule.append("i").append(getHCPosition(i)).append(pwd.charAt(i)).append(' ');
    }

    private String checkRuleSyntax(StringBuilder builder) {
        if (builder.length() == 0)
            return ":";

        String rule = builder.toString();
        if (rule.endsWith("  ") || rule.endsWith("$ ") || rule.endsWith("^ "))
            return rule.trim() + " ";

        return rule.trim();
    }

    public String checkCharRepetitions(String text, StringBuilder rule, int minRep) {
        String word = text;
        String temp = text + '\n' + '\n';
        if (enhancedCopy) {
            rule.append("M ");
        }

        int r = 0;
        for (int t = 0; t < temp.length() - 2; t++) {
            while (    temp.charAt(t + 0) == temp.charAt(t + 1)
                    && ((minRep == 1) || temp.charAt(t + 1) == temp.charAt(t + 2))) {

                if (enhancedCopy)
                    rule.append("X").append(getHCPosition(r + 1)).append('1').append(getHCPosition(t)).append(' ');
                else
                    addInsertRule(rule, t, temp);

                word = word.substring(0, r) + word.substring(r + 1);
                t++;
            }
            r++;
        }
        return word;
    }

    private String getAugmentNumberRule(String pwd, String deflated, int repeat, boolean reverse, boolean mayBeDate) {
        StringBuilder rule = new StringBuilder(pwd.length() * 3);
        int i = 0;
        if (!mayBeDate) {
            if (repeat > 0) rule.append('p').append(repeat).append(' ');
            else if (reverse) rule.append("f ");
            else checkCharRepetitions(deflated, rule, 1);
        }

        int s = 0;
        int e = pwd.length() - 1;
        while (s <= e && !isNumber(pwd.charAt(s))) s++;
        while (s <= e && !isNumber(pwd.charAt(e))) e--;

        addPrefixRule(rule, s, pwd);

        for (i = s; i < e; i++) {
            if (!isNumber(pwd.charAt(i))) {
                addInsertRule(rule, i, pwd);
            }
        }

        addSuffixRule(rule, e, pwd);
        return checkRuleSyntax(rule);
    }

    private String getAugmentSymbolRule(String pwd, int repeat, boolean reverse) {
        StringBuilder rule = new StringBuilder(pwd.length() * 3);
        int i = 0;
        if (repeat > 0) rule.append('p').append(repeat).append(' ');
        if (reverse) rule.append("f ");

        int s = 0;
        int e = pwd.length() - 1;
        while (s <= e && !isSymbol(pwd.charAt(s))) s++;
        while (s <= e && !isSymbol(pwd.charAt(e))) e--;

        addPrefixRule(rule, s, pwd);

        for (i = s; i < e; i++) {
            if (!isSymbol(pwd.charAt(i))) {
                addInsertRule(rule, i, pwd);
            }
        }

        addSuffixRule(rule, e, pwd);
        return checkRuleSyntax(rule);
    }

    private String getAugmentEmailRule(String afterAt) {
        StringBuilder rule = new StringBuilder((afterAt.length() + 1) * 2);
        rule.append("$@");
        for (char c : afterAt.toCharArray())
            rule.append('$').append(c);
        return rule.toString();
    }

    private String getAugmentTextRule(String text, String lower, String pwd, int repeat, boolean reverse, int minRep) {
        StringBuilder rule = new StringBuilder(pwd.length() * 3);
        int i = 0;
        if (repeat > 0) rule.append('p').append(repeat).append(' ');
        else if (reverse) rule.append("f ");
        else checkCharRepetitions(lower, rule, minRep);

        int s = 0;
        int e = pwd.length() - 1;
        while (s <= e && !isAlpha(pwd.charAt(s))) s++;
        while (s <= e && !isAlpha(pwd.charAt(e))) e--;

        addPrefixRule(rule, s, pwd);

        if (text.equals(text.toUpperCase())) {
            rule.append("t ");
            for (i = s; i < e; i++) {
                if (!isAlpha(pwd.charAt(i))) {
                    addInsertRule(rule, i, pwd);
                }
            }
        } else {
            for (i = s; i <= e; i++) {
                if (isAlpha(pwd.charAt(i))) {
                    if (isUpper(pwd.charAt(i))) { rule.append("T").append(getHCPosition(i)).append(' '); }
                } else {
                    addInsertRule(rule, i, pwd);
                }
            }
        }

        addSuffixRule(rule, e, pwd);
        return checkRuleSyntax(rule);
    }

    public static boolean mayBeDate(String test) {
        for (DateTimeFormatter pattern : DATES)
            try {
                LocalDate localDate = LocalDate.parse(test, pattern);
                if (!localDate.isBefore(MIN_DATE) && !localDate.isAfter(MAX_DATE))
                    return true;
            } catch (DateTimeParseException ignored) {
            }
        // no pattern matches...
        return false;
    }
    private String getConvertTextRule(String text, String unwrapped, String pwd, int repeat) {

        boolean abort = false;
        StringBuilder rule = new StringBuilder(pwd.length() * 3);
        Map<String, String> replaces = new HashMap<>(pwd.length());
        if (repeat > 0) rule.append('p').append(repeat).append(' ');
        int tsCount = 0;
        int s = pwd.indexOf(unwrapped);
        int e = s + unwrapped.length();

        addPrefixRule(rule, s, pwd);

        if (text.equals(text.toUpperCase())) {
            rule.append("t ");
            for (int i = s; i < e; i++) {
                char c = pwd.charAt(i);
                if (!isAlpha(c)) {
                    String r = getReplacingChar(c);
                    if (!r.isEmpty()) {
                        String subst = replaces.get(r);
                        if (subst != null && !subst.equals("" + c)) {
                            abort = true;
                            break;
                        } else
                            replaces.put(r, "" +c);
                    }
                }
                i++;
            }
        } else {
            for (int i = s; i < e; i++) {
                char c = pwd.charAt(i);
                if (isUpper(c)) {
                    rule.append("T").append(getHCPosition(i)).append(' ');
                    tsCount++;
                } else if (!isLower(c)) {
                    String r = getReplacingChar(c);
                    if (!r.isEmpty()) {
                        String subst = replaces.get(r);
                        if (subst != null && !subst.equals("" + c)) {
                            abort = true;
                            break;
                        } else
                            replaces.put(r, "" + c);
                    }
                }
            }
        }
        if (abort)
            // not a good candidate -> there are different substitution for the same letter
            return "";

        if (replaces.isEmpty())
            return "";
        else {
            List<String> sub = new ArrayList<>(replaces.size());
            for (String key : replaces.keySet()) {
                sub.add("s" + key + replaces.get(key));
            }
            Collections.sort(sub);
            rule.append(StringUtils.join(sub, ' ')).append(" ");
        }
        addSuffixRule(rule, e - 1, pwd);
        return checkRuleSyntax(rule);
    }

    public static String deflate(String l) {
        for (int maxrep = 10; maxrep > 1; maxrep--) {
            if (l.length() % maxrep == 0 && l.length() > 2 * maxrep) {
                String part = l.substring(0, l.length() / maxrep);
                int rep = 1;
                boolean skip = false;
                while (rep < maxrep && !skip) {
                    if (!part.equals(l.substring(l.length() / maxrep * rep, l.length() / maxrep * (rep + 1))))
                        skip = true;
                    rep++;
                }
                if (!skip)
                    return part;
            }
        }
        return l;
    }

    private String replaceChars(String l) {
        StringBuilder res = new StringBuilder(l.length() + 2);
        for (int i = 0; i < l.length(); i++) {
            char c = l.charAt(i);
            int pos = REPLACEABLE.indexOf(c);
            if (pos >= 0)
                res.append(REPLACED.charAt(pos));
            else // if (isAlpha(c))
                res.append(c);
        }
        return res.toString();
    }

    private String getReplacingChar(char c) {
        int pos = REPLACEABLE.indexOf(c);
        if (pos >= 0)
            return "" + REPLACED.charAt(pos);
        return "";
    }

    private String reverseString(String l) {
        StringBuilder res = new StringBuilder(l);
        return res.reverse().toString();
    }

    private static String getHCPosition(Integer i) {
        // converts the integer position of a character to the HashCat notation
        if (i < 10)
            return i.toString(); // 5 -> 5

        i = i - 10 + 65;
        char result = (char) i.intValue(); // 12 ->  C
        return "" + result;
    }

    public boolean transform(String pwd) {
        if (pwd != null && !pwd.isEmpty()) {
            pwd = pwd.replace("\\\\", "\\");
            CharType pwdType = detectMainComponent(pwd);

            String word1 = null, rule1 = null, word2 = null, rule2 = null, word3 = null, rule3 = null;

            if (types.contains(pwdType)) {
                switch (pwdType) {
                    case Email: {
                        String beforeAt = StringUtils.substringBefore(pwd, "@");
                        String rule = getAugmentEmailRule(StringUtils.substringAfter(pwd, "@"));
                        //                    record(beforeAt, words);                     //
                        addToMap(rule, rules);
                        logDebug(pwd + "::" + rule);
                        break;
                    }
                    case Alpha: {
                        // (mostly) alphabetic pwds

                        String text = extractPart(pwd, CharType.Alpha);
                        String lowerText = text.toLowerCase();
                        String deflated = deflate(lowerText);
                        int repeat = lowerText.length() / deflated.length() - 1;
                        String reverse = "";
                        boolean isReflected = false;
                        if (repeat == 0) {
                            reverse = reverseString(lowerText);
                            isReflected = deflated.equals(reverse) && deflated.length() >= 6 && deflated.length() % 2 == 0;
                        }
                        if (isReflected) {
                            word1 = reverse.substring(0, reverse.length() / 2);
                        } else if (repeat > 0) {
                            word1 = deflated;
                        } else {
                            StringBuilder rule = new StringBuilder();
                            word1 = checkCharRepetitions(lowerText, rule, 2);
                            word2 = checkCharRepetitions(lowerText, rule, 1);
                        }
                        rule1 = getAugmentTextRule(text, lowerText, pwd, repeat, isReflected, 2);

                        addToMap(word1, words);
                        addToMap(rule1, rules);
                        logDebug(pwd + ":" + word1 + ":" + rule1);

                        if (word2 != null && !word1.equals(word2)) {
                            rule2 = getAugmentTextRule(text, lowerText, pwd, repeat, false, 1);

                            addToMap(word2, words);
                            addToMap(rule2, rules);
                            logDebug(pwd + ":" + word2 + ":" + rule2);
                        }

                        String unwrapped = removeWrapper(pwd, CharType.Alpha);
                        if (unwrapped.length() > 0) {
                            String replaced = replaceChars(unwrapped);
                            if (StringUtils.isAlpha(replaced) && !replaced.equals(unwrapped)) {
                                lowerText = replaced.toLowerCase();
                                word3 = deflate(lowerText);
                                rule3 = getConvertTextRule(
                                        replaced,
                                        unwrapped,
                                        pwd,
                                        lowerText.length() / word3.length() - 1);

                                if (!rule3.isEmpty()) {
                                    addToMap(word3, words);
                                    addToMap(rule3, rules);
                                    logDebug(pwd + ":" + word3 + ":" + rule3);
                                }
                            }
                        }
                        break;
                    }
                    case Numeric: {
                        // (mostly) numeric pwds

                        //                    if (pwd.equals("***1998***"))
                        //                        System.out.println("DEBUG");
                        String num = extractPart(pwd, CharType.Numeric);
                        boolean mayBeDate = mayBeDate(num);
                        int repeat = 0;
                        boolean isReflected = false;
                        String deflated = num;
                        if (mayBeDate) {
                            word1 = num;
                        } else {
                            deflated = deflate(num);
                            repeat = num.length() / deflated.length() - 1;
                            String reverse = repeat == 0 ? reverseString(num) : "";
                            isReflected = deflated.equals(reverse) && deflated.length() >= 6 && deflated.length() % 2 == 0;
                            if (isReflected) {
                                word1 = reverse.substring(0, reverse.length() / 2);
                            } else if (repeat > 0) {
                                word1 = deflated;
                            } else {
                                StringBuilder rule = new StringBuilder();
                                word1 = checkCharRepetitions(num, rule, 1);
                            }
                        }
                        rule1 = getAugmentNumberRule(pwd, deflated, repeat, isReflected, mayBeDate);

                        addToMap(word1, words);
                        addToMap(rule1, rules);
                        logDebug(pwd + ":" + word1 + ":" + rule1);
                        break;
                    }
                    default: {
                        // very mixed chars

                        String symbols = extractPart(pwd, CharType.Symbol);
                        String deflated = deflate(symbols);
                        int repeat = symbols.length() / deflated.length() - 1;
                        String reverse = repeat == 0 ? reverseString(symbols) : "";
                        boolean isReflected = deflated.equals(reverse) && deflated.length() >= 6 && deflated.length() % 2 == 0;

                        if (isReflected) {
                            word1 = reverse.substring(0, reverse.length() / 2);
                        } else {
                            word1 = deflated;
                        }

                        rule1 = getAugmentSymbolRule(pwd, repeat, isReflected);
                        addToMap(word1, words);
                        addToMap(rule1, rules);
                        logDebug(pwd + ":" + word1 + ":" + rule1);
                        break;
                    }
                }
            }
        }
        return true;
    }

    public Map<String, Integer> getWords() {
        return words;
    }

    public Map<String, Integer> getRules() {
        return rules;
    }

    public void setEnhancedCopy(boolean value) {
        enhancedCopy = value;
    }
    public void setDebug(File debug) {
        try {
            this.debug = new BufferedOutputStream(new FileOutputStream(debug));
        } catch (IOException e) {
        }
    }

    public void logDebug(String row) {
        if (this.debug != null)
            try {
                this.debug.write(row.getBytes());
                this.debug.write("\n".getBytes());
            } catch (IOException e) {
            }
    }

}
