/*
 * Main File for testing Ciphers
 * <p/>
 * BITS F463 - Group 7
 * <p/>
 */

import java.util.Scanner; 

public class Main {
    private static AES cipherAES;

    public static void main(String[] args) {
        byte[] key = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\5".getBytes();
        System.out.print("Key: ");
        printHexString(key);

        Scanner sc = new Scanner(System.in);
        System.out.print("Enter Plaintext: ");  
        String text = sc.nextLine();

        text = fillBlock(text);
        byte[] inputText = text.getBytes();

        // AES test
        byte[] iv = "c8IKDNGsbioSCfxWa6KT8A84SrlMwOUH".getBytes();
        cipherAES = new AES(key, iv);

        byte[] retAes = cipherAES.CBC_encrypt(inputText);
        System.out.print("AES Encrypted Data: ");
        printHexString(retAes);

        byte[] originAes = cipherAES.CBC_decrypt(retAes);

        System.out.print("AES Decrypted Data: ");
        System.out.println(new String(originAes));

        // ChaCha Test
        byte[] nonce = "\0\0\0\0\0\0\0\0\0\0\0\5".getBytes();

        ChaCha20 cipher = new ChaCha20(key, nonce, 0);
        byte[] ret = new byte[inputText.length];
        cipher.encrypt(ret, inputText, inputText.length);

        System.out.print("ChaCha20 Encrypted Data: ");
        printHexString(ret);


        ChaCha20 decoder = new ChaCha20(key, nonce, 0);
        byte[] origin = new byte[ret.length];
        decoder.encrypt(origin, ret, ret.length);

        System.out.print("ChaCha20 Decrypted Data: ");
        System.out.println(new String(origin));

        System.out.println("Running 100000 iterations on both...");

        double startTimeAES = System.currentTimeMillis();
        for (int i=0; i < 100000; i++) cipherAES.CBC_decrypt(cipherAES.CBC_encrypt(inputText));
        double endTimeAES = System.currentTimeMillis();
        
        double startTimeChaCha = System.currentTimeMillis();
        for (int i=0; i < 100000; i++){
            cipher.encrypt(ret, inputText, inputText.length);
            decoder.encrypt(origin, ret, ret.length);
        } 
        double endTimeChaCha = System.currentTimeMillis();
        System.out.println("AES    | "+(endTimeAES-startTimeAES)/1000.0 + " secs");
        System.out.println("ChaCha | "+(endTimeChaCha-startTimeChaCha)/1000.0 + " secs");
    }

    private static String fillBlock(String text) {
        int spaceNum = text.getBytes().length%16==0?0:16-text.getBytes().length%16;
        for (int i = 0; i<spaceNum; i++) text += " ";
        return text;
    }

    private static byte[] getKey() {
        String key = "";
        for (int i=0; i < 2; i++) key += Long.toHexString(Double.doubleToLongBits(Math.random()));
        return key.getBytes();
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
}
