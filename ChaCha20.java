/*
 * ChaCha 256-bit Cipher Implementation
 * <p/>
 * BITS F463 - Group 7
 * <p/>
 */

import java.util.Scanner; 

public class ChaCha20 {
    //Key size in bytes
    public static final int KEY_SIZE = 32;

    //Nonce size in bytes
    public static final int NONCE_SIZE = 12;

    private int[] matrix = new int[16];

    //Converts Little Endian Format to Integer Data
    protected static int littleEndianToInt(byte[] bs, int i) {
        return (bs[i] & 0xff) | ((bs[i + 1] & 0xff) << 8) | ((bs[i + 2] & 0xff) << 16) | ((bs[i + 3] & 0xff) << 24);
    }

    //Converts Integer Data to Little Endian Format
    protected static void intToLittleEndian(int n, byte[] bs, int off) {
        bs[  off] = (byte)(n       );
        bs[++off] = (byte)(n >>>  8);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 24);
    }

    //Rotate Method
    protected static int ROTATE(int v, int c) {
        return (v << c) | (v >>> (32 - c));
    }

    //Quarter Round as described in the original paper
    protected static void quarterRound(int[] x, int a, int b, int c, int d) {
        x[a] += x[b];
        x[d] = ROTATE(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = ROTATE(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = ROTATE(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = ROTATE(x[b] ^ x[c], 7);
    }

    //Incompatible Nonce Error
    public class WrongNonceSizeException extends Exception {
        public WrongNonceSizeException (String str) {  
            super(str);  
        }  
    }

    //Incompatible Key Error
    public class WrongKeySizeException extends Exception {
        public WrongKeySizeException (String str) {  
            super(str);  
        } 
    }

    //Initialization of the ChaCha matrix as described in the original paper
    /*
    * constant constant constant constant
    * key      key      key      key
    * key      key      key      key
    * input    input    input    input
    */
    public ChaCha20(byte[] key, byte[] nonce, int counter)
        throws WrongKeySizeException, WrongNonceSizeException {

        if (key.length != KEY_SIZE) {
            throw new WrongKeySizeException("Key Error");
        }

        this.matrix[ 0] = 0x61707865;
        this.matrix[ 1] = 0x3320646e;
        this.matrix[ 2] = 0x79622d32;
        this.matrix[ 3] = 0x6b206574;
        this.matrix[ 4] = littleEndianToInt(key, 0);
        this.matrix[ 5] = littleEndianToInt(key, 4);
        this.matrix[ 6] = littleEndianToInt(key, 8);
        this.matrix[ 7] = littleEndianToInt(key, 12);
        this.matrix[ 8] = littleEndianToInt(key, 16);
        this.matrix[ 9] = littleEndianToInt(key, 20);
        this.matrix[10] = littleEndianToInt(key, 24);
        this.matrix[11] = littleEndianToInt(key, 28);

        if (nonce.length == NONCE_SIZE) {
            this.matrix[12] = counter;
            this.matrix[13] = littleEndianToInt(nonce, 0);
            this.matrix[14] = littleEndianToInt(nonce, 4);
            this.matrix[15] = littleEndianToInt(nonce, 8);
        } else {
            throw new WrongNonceSizeException("Nonce Error");
        }
    }

    //ChaCha20 encryption method
    public void encrypt(byte[] dst, byte[] src, int len) {
        int[] x = new int[16];
        byte[] output = new byte[64];
        int i, dpos = 0, spos = 0;

        while (len > 0) {
            for (i = 16; i-- > 0; ) x[i] = this.matrix[i];

            //Repeat 20 rounds
            for (i = 20; i > 0; i -= 2) {
                quarterRound(x, 0, 4,  8, 12);
                quarterRound(x, 1, 5,  9, 13);
                quarterRound(x, 2, 6, 10, 14);
                quarterRound(x, 3, 7, 11, 15);
                quarterRound(x, 0, 5, 10, 15);
                quarterRound(x, 1, 6, 11, 12);
                quarterRound(x, 2, 7,  8, 13);
                quarterRound(x, 3, 4,  9, 14);
            }

            for (i = 16; i-- > 0; ) x[i] += this.matrix[i];
            for (i = 16; i-- > 0; ) intToLittleEndian(x[i], output, 4 * i);

            //Increment counter and handle overflow
            this.matrix[12] += 1;
            if (this.matrix[12] <= 0) {
                this.matrix[13] += 1;
            }
            
            //Generate output using Matrix values & Input Data
            if (len <= 64) {
                //This is only entered for incomplete blocks with less than 64 bytes of data
                for (i = len; i-- > 0; ) {
                    dst[i + dpos] = (byte) (src[i + spos] ^ output[i]);
                }
                return;
            }

            for (i = 64; i-- > 0; ) {
                dst[i + dpos] = (byte) (src[i + spos] ^ output[i]);
            }

            //Decrement the length
            //Increment the source & destination pointers
            len -= 64;
            spos += 64;
            dpos += 64;
        }
    }

    public static void printHexString(byte[] b) {
        for (int i = 0; i < b.length; i++) {
            String hex = Integer.toHexString(b[i] & 0xFF);
            if (hex.length() == 1) {
                hex = '0' + hex;
            }
            System.out.print(hex.toUpperCase());

        }
        System.out.println();
    }

    public static void main(String[] args) {
        byte[] key = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\5".getBytes();
        System.out.print("Key: ");
        printHexString(key);
        byte[] nonce = "\0\0\0\0\0\0\0\0\0\0\0\5".getBytes();

        Scanner sc = new Scanner(System.in);
        System.out.print("Enter Plaintext: ");  
        String str = sc.nextLine();

        byte[] plaintext = str.getBytes();

        try {
            ChaCha20 cipher = new ChaCha20(key, nonce, 0);
            byte[] ret = new byte[plaintext.length];
            cipher.encrypt(ret, plaintext, plaintext.length);

            System.out.print("Encrypted Data: ");
            printHexString(ret);


            ChaCha20 decoder = new ChaCha20(key, nonce, 0);
            byte[] origin = new byte[ret.length];
            decoder.encrypt(origin, ret, ret.length);

            System.out.print("Decrypted Data: ");
            System.out.println(new String(origin));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
