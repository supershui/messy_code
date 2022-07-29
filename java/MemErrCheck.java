import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

public class MemErrCheck {

    public static final String PARAM_KEY_MEM_SIZE_LONG = "--mem-size";
    public static final String PARAM_KEY_MEM_SIZE_SHORT = "-ms";

    public static final String PARAM_KEY_ROUND_LONG = "--round";
    public static final String PARAM_KEY_ROUND_SHORT = "-r";


    private final long mMemBlockSize;
    private final int mRounds;
    private final int mInnerLoops = 16;

    private int mCurrentMode;
    private boolean mCurrentRandom;
    private BigInteger mTotalWriteBytes = BigInteger.valueOf(0);
    private List<ErrRec> mErrorRecords = new ArrayList<>(10);

    private static class ErrRec {
        public final int src;
        public final int dest;
        public final int mode;
        public final boolean random;
        public final BigInteger writeBytes;

        public ErrRec(int src, int dest, int mode, boolean random, BigInteger writeBytes) {
            this.src = src;
            this.dest = dest;
            this.mode = mode;
            this.random = random;
            this.writeBytes = writeBytes;
        }

        @Override
        public String toString() {
            return "ErrRec{src:" + intToBinStr(src) + ";dest:" + intToBinStr(dest) + ";mode:" + mode + ";random:" + random + ";write:" + writeBytes + "}";
        }
    }


    public MemErrCheck(long memSize, int rounds) {
        mMemBlockSize = memSize;
        mRounds = rounds;
    }

    public static void main(String[] args) {
        MemErrCheck mec = parseArgs(args);
        if (mec == null) {
            usage();
            return;
        }

        mec.check();
    }

    private static void usage() {
        System.out.println("usage:");
        System.out.println("java " + MemErrCheck.class.getCanonicalName() + " ["
                + PARAM_KEY_MEM_SIZE_LONG + "|" + PARAM_KEY_MEM_SIZE_SHORT + "] <mem_block_size> ["
                + PARAM_KEY_ROUND_LONG + "|" + PARAM_KEY_ROUND_SHORT + "] <rounds>");
    }

    private static MemErrCheck parseArgs(String[] args) {
        if (args == null || args.length != 4) {
            System.out.println("parseArgs: Invalid arg length");
            return null;
        }

        long memSize = -1;
        int rounds = -1;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (PARAM_KEY_MEM_SIZE_LONG.equals(arg) || PARAM_KEY_MEM_SIZE_SHORT.equals(arg)) {
                i++;
                if (i < args.length) {
                    memSize = parseMemSize(args[i]);
                }
            } else if (PARAM_KEY_ROUND_LONG.equals(arg) || PARAM_KEY_ROUND_SHORT.equals(arg)) {
                i++;
                if (i < args.length) {
                    rounds = Integer.parseInt(args[i]);
                }
            } else {
                System.out.println("parseArgs: unrecognized arg " + arg);
            }
        }

        if (memSize <= 0 || rounds <= 0) {
            System.out.println("parseArgs: Invalid memSize and rounds. memSize=" + memSize + "; rounds=" + rounds);
            return null;
        }

        return new MemErrCheck(memSize, rounds);
    }

    private static long parseMemSize(String memSizeStr) {
        if (memSizeStr == null || memSizeStr.length() == 0) {
            System.out.println("parseMemSize: empty memSizeStr.");
            return -1;
        }

        long factor = 1;
        if (memSizeStr.endsWith("K") || memSizeStr.endsWith("k")) {
            factor = 1024L;
            memSizeStr = memSizeStr.substring(0, memSizeStr.length() - 1);
        } else if (memSizeStr.endsWith("M") || memSizeStr.endsWith("m")) {
            factor = 1024L * 1024L;
            memSizeStr = memSizeStr.substring(0, memSizeStr.length() - 1);
        } else if (memSizeStr.endsWith("G") || memSizeStr.endsWith("g")) {
            factor = 1024L * 1024L * 1024L;
            memSizeStr = memSizeStr.substring(0, memSizeStr.length() - 1);
        } else if (memSizeStr.endsWith("T") || memSizeStr.endsWith("t")) {
            factor = 1024L * 1024L * 1024L * 1024L;
            memSizeStr = memSizeStr.substring(0, memSizeStr.length() - 1);
        } else if (memSizeStr.endsWith("P") || memSizeStr.endsWith("p")) {
            factor = 1024L * 1024L * 1024L * 1024L * 1024L;
            memSizeStr = memSizeStr.substring(0, memSizeStr.length() - 1);
        } else if (memSizeStr.endsWith("E") || memSizeStr.endsWith("e")) {
            factor = 1024L * 1024L * 1024L * 1024L * 1024L * 1024L;
            memSizeStr = memSizeStr.substring(0, memSizeStr.length() - 1);
        } else if (memSizeStr.endsWith("Z") || memSizeStr.endsWith("z")) {
            factor = 1024L * 1024L * 1024L * 1024L * 1024L * 1024L * 1024L;
            memSizeStr = memSizeStr.substring(0, memSizeStr.length() - 1);
        } else if (memSizeStr.endsWith("Y") || memSizeStr.endsWith("y")) {
            factor = 1024L * 1024L * 1024L * 1024L * 1024L * 1024L * 1024L * 1024L;
            memSizeStr = memSizeStr.substring(0, memSizeStr.length() - 1);
        }

        long memSize = Long.parseLong(memSizeStr);
        System.out.println("parseMemSize: memSize=" + memSize + "; factor=" + factor);
        return memSize * factor;
    }

    public static String makeTimeStr(Calendar cal) {
        char[] buf = new char[23];
        int year = cal.get(Calendar.YEAR);
        int month = cal.get(Calendar.MONTH) + 1;
        int day = cal.get(Calendar.DAY_OF_MONTH);
        int hour = cal.get(Calendar.HOUR_OF_DAY);
        int minute = cal.get(Calendar.MINUTE);
        int second = cal.get(Calendar.SECOND);
        int millisecond = cal.get(Calendar.MILLISECOND);
        buf[0] = (char) ('0' + (year / 1000));
        buf[1] = (char) ('0' + ((year % 1000) / 100));
        buf[2] = (char) ('0' + ((year % 100) / 10));
        buf[3] = (char) ('0' + (year % 10));
        buf[4] = '-';
        buf[5] = (char) ('0' + (month / 10));
        buf[6] = (char) ('0' + (month % 10));
        buf[7] = '-';
        buf[8] = (char) ('0' + (day / 10));
        buf[9] = (char) ('0' + (day % 10));
        buf[10] = ' ';
        buf[11] = (char) ('0' + (hour / 10));
        buf[12] = (char) ('0' + (hour % 10));
        buf[13] = ':';
        buf[14] = (char) ('0' + (minute / 10));
        buf[15] = (char) ('0' + (minute % 10));
        buf[16] = ':';
        buf[17] = (char) ('0' + (second / 10));
        buf[18] = (char) ('0' + (second % 10));
        buf[19] = '.';
        buf[20] = (char) ('0' + (millisecond / 100));
        buf[21] = (char) ('0' + ((millisecond % 100) / 10));
        buf[22] = (char) ('0' + (millisecond % 10));
        return new String(buf);
    }


    public static String intToBinStr(int n) {
        char[] buf = new char[32];
        for (int i = 0; i < buf.length; i++) {
            buf[i] = (n & 0x80000000) == 0 ? '0' : '1';
            n <<= 1;
        }
        return new String(buf);
    }


    public static void logln(String msg) {
        Calendar cal = Calendar.getInstance();
        System.out.println(makeTimeStr(cal) + ": " + msg);
    }

    public static void log(String msg) {
        Calendar cal = Calendar.getInstance();
        System.out.print(makeTimeStr(cal) + ": " + msg);
    }


    public void check() {
        System.out.println("================ start check ================");
        System.out.println("Memory block size: " + mMemBlockSize);
        System.out.println("Rounds: " + mRounds);

        boolean overallResult = true;
        boolean roundResult;
        boolean result;

        long begin = System.nanoTime();
        for (int i = 0; i < mRounds; i++) {
            logln("check: start round " + i);
            long loopBegin = System.nanoTime();

            roundResult = true;
            result = checkWithMode(0x00000000);
            roundResult = roundResult && result;

            result = checkWithMode(0x55555555);
            roundResult = roundResult && result;

            result = checkWithMode(0xAAAAAAAA);
            roundResult = roundResult && result;

            result = checkWithMode(0x33333333);
            roundResult = roundResult && result;

            result = checkWithMode(0xCCCCCCCC);
            roundResult = roundResult && result;

            result = checkWithMode(0x0F0F0F0F);
            roundResult = roundResult && result;

            result = checkWithMode(0xF0F0F0F0);
            roundResult = roundResult && result;

            result = checkWithMode(0x87878787);
            roundResult = roundResult && result;

            result = checkWithMode(0x78787878);
            roundResult = roundResult && result;

            result = checkWithMode(0x1E1E1E1E);
            roundResult = roundResult && result;

            result = checkWithMode(0xE1E1E1E1);
            roundResult = roundResult && result;

            result = checkWithMode(0xC3C3C3C3);
            roundResult = roundResult && result;

            result = checkWithMode(0x3C3C3C3C);
            roundResult = roundResult && result;

            result = checkWithMode(0x00FF00FF);
            roundResult = roundResult && result;

            result = checkWithMode(0xFF00FF00);
            roundResult = roundResult && result;

            result = checkWithMode(0x0000FFFF);
            roundResult = roundResult && result;

            result = checkWithMode(0xFFFF0000);
            roundResult = roundResult && result;

            result = checkWithMode(0xFFFFFFFF);
            roundResult = roundResult && result;

            result = checkWithRandom();
            roundResult = roundResult && result;

            long loopEnd = System.nanoTime();

            logln("check: round " + i + " result " + roundResult + "; time cost " + ((loopEnd-loopBegin)/1000) + " us. Bytes written " + mTotalWriteBytes + ".");

            overallResult = overallResult && roundResult;

        }
        long end = System.nanoTime();
        logln("check: overall result " + overallResult + "; time cost " + ((end-begin)/1000) + " us. Bytes written " + mTotalWriteBytes + ".");

        dumpErrors();
    }


    private void dumpErrors() {
        logln("dumpErrors: total errors " + mErrorRecords.size());

        for (int i = 0; i < mErrorRecords.size(); i++) {
            logln("dumpErrors: err[" + i + "]=" + mErrorRecords.get(i));
        }
    }

    private int[][] initMemWithMode(int mode) {
        final int segSize = 1024 * 1024 * 1024;
        int segCount = (int) ((mMemBlockSize + segSize - 1) / segSize);
        int remainder = (int) (mMemBlockSize % segSize);

        int[][] source = new int[segCount][];
        for (int i = 0; i < segCount; i++) {
            int size = ((i == (segCount - 1)) && (remainder != 0)) ? remainder : segSize;
            source[i] = new int[size];
            for (int j = 0; j < size; j++) {
                source[i][j] = mode;
            }
        }
        incTotalWriteBytes(mMemBlockSize << 2);

        return source;
    }

    private void incTotalWriteBytes(long bytes) {
        if (bytes <= 0) {
            return;
        }

        mTotalWriteBytes = mTotalWriteBytes.add(BigInteger.valueOf(bytes));
    }

    private int[][] initWithRandom() {
        final int segSize = 1024 * 1024 * 1024;
        int segCount = (int) ((mMemBlockSize + segSize - 1) / segSize);
        int remainder = (int) (mMemBlockSize % segSize);

        int[][] source = new int[segCount][];
        for (int i = 0; i < segCount; i++) {
            int size = ((i == (segCount - 1)) && (remainder != 0)) ? remainder : segSize;
            source[i] = new int[size];
        }

        SecureRandom sr;
        try {
            sr = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return source;
        }

        for (int i = 0; i < segCount; i++) {
            int len = source[i].length;
            for (int j = 0; j < len; j++) {
                source[i][j] = sr.nextInt();
            }
        }
        incTotalWriteBytes(mMemBlockSize << 2);


        return source;
    }

    private boolean checkMemWithMode(int[][] mem, int mode) {
        for (int i = 0; i < mem.length; i++) {
            int len = mem[i].length;
            for (int j = 0; j < len; j++) {
                if (mem[i][j] != mode) {
                    logln("checkMemWithMode: mem[" + i + "][" + j + "] failed, expected " + intToBinStr(mode) + "; got " + intToBinStr(mem[i][j]) + "; total written " + mTotalWriteBytes);
                    return false;
                }
            }
        }
        return true;
    }

    private int[][] makeDestination(int[][] source) {
        int[][] dest = new int[source.length][];
        for (int i = 0; i < source.length; i++) {
            dest[i] = new int[source[i].length];
        }
        return dest;
    }

    private void cpArrays(int[][] source, int[][] destination) {
        for (int i = 0; i < source.length; i++) {
            System.arraycopy(source[i], 0, destination[i], 0, source[i].length);
            incTotalWriteBytes(source[i].length << 2);
        }
    }

    private void saveToErrorRecords(int src, int dest) {
        ErrRec er = new ErrRec(src, dest, mCurrentMode, mCurrentRandom, mTotalWriteBytes);
        mErrorRecords.add(er);
    }

    private boolean checkArrays(int[][] source, int[][] destination) {
        for (int i = 0; i < source.length; i++) {
            int len = source[i].length;
            for (int j = 0; j < len; j++) {
                if (source[i][j] != destination[i][j]) {
                    logln("checkArrays: src[" + i + "][" + j + "]=" + intToBinStr(source[i][j]) + "; dest[" + i + "][" + j + "]=" + intToBinStr(destination[i][j]) + "; total written " + mTotalWriteBytes);
                    saveToErrorRecords(source[i][j], destination[i][j]);
                    return false;
                }
            }
        }
        return true;
    }

    private boolean checkWithMode(int mode) {
        logln("checkWithMode: " + intToBinStr(mode));
        mCurrentMode = mode;
        mCurrentRandom = false;

        int[][] source = initMemWithMode(mode);
        logln("checkWithMode: initialized source");
        boolean srcCheck = checkMemWithMode(source, mode);
        logln("checkWithMode: source check " + srcCheck);
        if (!srcCheck) {
            return false;
        }

        boolean overallResult = true;
        int[][] destionation = makeDestination(source);

        log("checkWithMode: checking destionation for " + mInnerLoops + " loops ......");
        for (int i = 0; i < mInnerLoops; i++) {
            cpArrays(source, destionation);
            boolean result = checkArrays(source, destionation);
            overallResult = overallResult && result;
        }
        System.out.println((overallResult ? " SUCCESS" : " FAIL") + " ========");

        return overallResult;
    }


    private boolean checkWithRandom() {
        logln("checkWithRandom: ");
        mCurrentMode = 0;
        mCurrentRandom = true;

        int[][] source = initWithRandom();
        logln("checkWithRandom: initialized source");

        boolean overallResult = true;
        int[][] destionation = makeDestination(source);

        int rounds = mInnerLoops * 16;
        log("checkWithRandom: checking destionation for " + rounds + " loops ......");
        for (int i = 0; i < rounds; i++) {
            cpArrays(source, destionation);
            boolean result = checkArrays(source, destionation);
            overallResult = overallResult && result;
        }
        System.out.println((overallResult ? " SUCCESS" : " FAIL") + " ========");

        return overallResult;
    }

}
