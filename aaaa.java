import org.buildobjects.process.ProcBuilder;

import java.io.*;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Scanner;
import java.util.StringTokenizer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
/**
 * Created by barisyagan on 11/16/16.
 */
public class aaaa {

    static Scanner reader = new Scanner(System.in);

    static ArrayList<FileObject> files = new ArrayList<>();
    //static ArrayList<String> subjects = new ArrayList<>();

    static String currentUser;

    static String command = "";
    static String argument1;
    static String argument2;
    static byte[] keyValue;


    public static void main(String[] args) throws Exception {





        //initiateSubjectList();
        File f = new File("SecureStore.dat");

        if (!f.createNewFile()) {
            new ProcBuilder("chmod").withArg("666").withArg("SecureStore.dat").run();
            readExistingSecureStore();
            signInSignUp();

            //System.out.println("Password: ");
            //String password = reader.next();
            char[] pass = PasswordField.getPassword(System.in, "UPassword: ");
            String password = String.valueOf(pass);
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] passwordHash = digest.digest(password.getBytes());

            if (!Arrays.equals(passwordHash, files.get(0).iv)) {
                System.exit(0);
            } else {
                keyValue = password.getBytes();
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                keyValue = sha.digest(keyValue);
            }

        }

        while (!command.equals("bye")) {

            if (files.size() == 0) {
                keyValue = new byte[] {'a','d','m','i','n','9','9','9','9'};
                MessageDigest digest = MessageDigest.getInstance("MD5");
                files.add(new FileObject("&&hj+loG2WE4", "", new byte[0], digest.digest(keyValue)));
                MessageDigest sha = MessageDigest.getInstance("SHA-256");
                keyValue = sha.digest(keyValue);
                signInSignUp();
            }

            System.out.println("Type: ");
            command = reader.next();
            try {




                FileOutputStream fos = new FileOutputStream("SecureStore.dat");
                ObjectOutputStream oos = new ObjectOutputStream(fos);





                run(command);

                oos.writeObject(files);
                oos.flush();
                oos.close();
                fos.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }


    }

    private static void signInSignUp() throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        String username = "";
        char[] password = null;
        char[] password2 = null;
        System.out.println("sign-in or sign-up");
        String command = reader.next();
        if (command.equals("sign-in")) {
            System.out.println("username: ");
            username = reader.next();
            if (files.get(0).subjects.contains(username)) {
                password =  PasswordField.getPassword(System.in, "password: ");
                //System.out.println("password");
                //password = reader.next().toCharArray();

                byte[] c = new byte[password.length + files.get(0).salts.get(getIndexOfUsername(username)).length];
                System.arraycopy(String.valueOf(password).getBytes(), 0, c, 0, password.length);
                System.arraycopy(files.get(0).salts.get(getIndexOfUsername(username)), 0, c, password.length, files.get(0).salts.get(getIndexOfUsername(username)).length);
                byte[] typedPasswordHash = sha.digest(c);
                if (Arrays.equals(typedPasswordHash, files.get(0).passwords.get(getIndexOfUsername(username)))) {
                    currentUser = username;
                } else {

                    signInSignUp();
                }
            } else {
                signInSignUp();
            }
        } else if (command.equals("sign-up")) {
            System.out.println("username: ");
            username = reader.next();
            password =  PasswordField.getPassword(System.in, "password: ");
            //System.out.println("password:");
            //password = reader.next().toCharArray();
            password2 = PasswordField.getPassword(System.in, "password again: ");
            //System.out.println("password again:");
            //password2 = reader.next().toCharArray();
            if (String.valueOf(password).equals(String.valueOf(password2))) {
                currentUser = username;
                files.get(0).subjects.add(username);
                SecureRandom randomSecure = new SecureRandom();
                byte[] salt = new byte[8];
                randomSecure.nextBytes(salt);
                byte[] c = new byte[password.length + salt.length];
                System.arraycopy(String.valueOf(password).getBytes(), 0, c, 0, password.length);
                System.arraycopy(salt, 0, c, password.length, salt.length);
                byte[] passwordHash = sha.digest(c);
                files.get(0).passwords.add(passwordHash);
                files.get(0).salts.add(salt);
            } else {
                System.out.println("password mismatch!");
                signInSignUp();
            }
        } else {
            signInSignUp();
        }
    }

    public static int getIndexOfUsername(String username) throws Exception {
        for (int i = 0; i < files.get(0).subjects.size(); i++) {
            if (username.equals(files.get(0).subjects.get(i)))
                return i;
        }
        return -1;
    }

    /*private static void initiateSubjectList() throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        new ProcBuilder("dscl").withArg(".").withArg("list").withArg("/Users").withOutputStream(output).run();
        String rawUserList = output.toString();

        StringTokenizer st = new StringTokenizer(rawUserList);
        int i = 0;
        while(st.hasMoreTokens()) {
            String token = st.nextToken();
            if (!token.startsWith("_") && !token.equals("daemon") && !token.equals("nobody") && !token.equals("root")) {
                subjects.add(token);
                i += 1;
            }
        }
        output.close();
    }*/

    private static void readExistingSecureStore() throws ClassNotFoundException, IOException {
        FileInputStream fis = new FileInputStream("SecureStore.dat");
        if (fis.available() > 0) {
            ObjectInputStream ois = new ObjectInputStream(fis);
            files = (ArrayList<FileObject>) ois.readObject();
            ois.close();
        }

        fis.close();
    }

    private static void run(String command) throws Exception {
        switch (command) {
            case "help":
                help();
                break;

            case "whoami":
                whoami();
                break;

            case "put":

                argument1 = reader.next();
                argument2 = reader.next();

                put(argument1, argument2);


                break;
            case "delete":

                argument1 = reader.next();

                delete(argument1);

                break;
            case "get":

                argument1 = reader.next();

                get(argument1);

                break;
            case "chown":

                argument1 = reader.next();
                argument2 = reader.next();

                chown(argument1, argument2);

                break;
            case "grant_r":

                argument1 = reader.next();
                argument2 = reader.next();

                grant_r(argument1, argument2);

                break;
            case "revoke_r":

                argument1 = reader.next();
                argument2 = reader.next();

                revoke_r(argument1, argument2);

                break;
            case "grant_w":

                argument1 = reader.next();
                argument2 = reader.next();

                grant_w(argument1, argument2);

                break;
            case "revoke_w":

                argument1 = reader.next();
                argument2 = reader.next();

                revoke_w(argument1, argument2);

                break;
            case "ls":

                ls();

                break;
            case "ls_all":

                ls_all();

                break;
            case "reorganize":

                reorganize();

                break;
            case "chpasswd":

                argument1 = reader.next();

                chpasswd(argument1);

                break;

            case "change_password":

                change_password();

                break;
        }

    }

    private static void change_password() throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        //System.out.println("current password:");
        //char[] password = reader.next().toCharArray();
        char[] password =  PasswordField.getPassword(System.in, "current password: ");
        byte[] c = new byte[password.length + files.get(0).salts.get(getIndexOfUsername(currentUser)).length];
        System.arraycopy(String.valueOf(password).getBytes(), 0, c, 0, password.length);
        System.arraycopy(files.get(0).salts.get(getIndexOfUsername(currentUser)), 0, c, password.length, files.get(0).salts.get(getIndexOfUsername(currentUser)).length);
        byte[] typedPasswordHash = sha.digest(c);
        if (Arrays.equals(typedPasswordHash, files.get(0).passwords.get(getIndexOfUsername(currentUser)))) {
            //System.out.println("new password:");
            //String newPassword = reader.next();
            char[] newPassword = PasswordField.getPassword(System.in, "new password: ");
            //System.out.println("new password again:");
            //String newPassword2 = reader.next();
            char[] newPassword2 = PasswordField.getPassword(System.in, "new password again: ");
            if (Arrays.equals(newPassword, newPassword2)) {
                SecureRandom randomSecure = new SecureRandom();
                byte[] salt2 = new byte[8];
                randomSecure.nextBytes(salt2);
                byte[] c2 = new byte[newPassword.length + salt2.length];
                System.arraycopy(String.valueOf(newPassword).getBytes(), 0, c2, 0, newPassword.length);
                System.arraycopy(salt2, 0, c2, newPassword.length, salt2.length);
                byte[] newPasswordHash = sha.digest(c2);
                files.get(0).salts.set(getIndexOfUsername(currentUser), salt2);
                files.get(0).passwords.set(getIndexOfUsername(currentUser),newPasswordHash);
            }
            else {
                System.out.println("two passwords were not same!");
            }
        } else {
            System.out.println("wrong password!");
        }

    }

    private static void chpasswd(String argument1) throws Exception {
        decryptAllMetaData();
        decryptAllContent();

        MessageDigest digest = MessageDigest.getInstance("MD5");
        files.get(0).iv = digest.digest(argument1.getBytes());

        MessageDigest digest2 = MessageDigest.getInstance("SHA-256");
        keyValue = digest2.digest(argument1.getBytes());



        for (int i = 1; i < files.size(); i++) {
            SecureRandom randomSecure = new SecureRandom();
            byte[] iv = new byte[16];
            randomSecure.nextBytes(iv);
            files.get(i).iv = iv;
        }

        encryptAllContent();
        encryptAllMetaData();
    }

    private static void help() {
        System.out.println("whoami: shows the current user who is using current program.\n" +
                "put [path_on_OS] [file_name]: puts the file at path_on_OS into the system with the given name file_name.\n" +
                "delete [file_name]: deletes the file which is in system and whose name is file_name.\n" +
                "get [String file_name]: writes out the file whose name is file_name and stored in our system to the current folder where program is executed.\n" +
                "chown [file_name] [subject]: changes the owner of file to the subject)\n" +
                "grant_r [file_name] [subject]: grants read permission to the subject.\n" +
                "revoke_r [file_name] [subject]: revokes read permission from the subject.\n" +
                "grant_w [file_name] [subject]: grants write permission to the subject.\n" +
                "revoke_w [file_name] [subject]: revokes write permission from the subject.\n" +
                "ls: shows all files and their permissions accesible by current user.\n" +
                "ls_all: shows all files and their permissions even the current user does not have read or write permission.\n" +
                "reorganize: reorganizes the main storage file by deleting the files from the storage that are deleted before.\n" +
                "bye: exists the program.");
    }

    private static void whoami() {
        System.out.println(currentUser);
    }

    private static void put(String path_on_OS, String file_name) throws Exception {
        FileObject file = getFile(file_name);
        if (file != null && file.deleted.equals("t")) {
            file.deleted = "f";
            encyptMetaData(file);
        } else if (file != null) {
            System.out.println("This file already exists!");
            encyptMetaData(file);
        } else {
            Path path = Paths.get(path_on_OS);

            SecureRandom randomSecure = new SecureRandom();
            byte[] iv = new byte[16];
            randomSecure.nextBytes(iv);

            byte[] data = encrypt(Files.readAllBytes(path), keyValue, iv).getBytes();

            FileObject newFile = new FileObject(file_name, currentUser, data, iv);
            encyptMetaData(newFile);
            files.add(newFile);
        }

    }

    private static void delete(String file_name) throws Exception {
        FileObject file = getFile(file_name);
        if (file == null) {
            System.out.println("There is no such a file!");
        } else {
            if (file.writePermission.contains(currentUser))
                file.deleted = "t";
            else
                System.out.println("Permission denied!");
        }
        encyptMetaData(file);
    }

    private static void get(String file_name) throws Exception {
        FileObject file = getFile(file_name);
        decryptContent(file);
        if (file == null) {
            System.out.println("There is no such a file!");
        } else {
            if (file.readPermission.contains(currentUser)) {
                RandomAccessFile newFile = new RandomAccessFile("./" + file_name, "rw");
                newFile.write(file.fileContent);
            } else {
                System.out.println("Permission denied!");
            }
        }
        encyptMetaData(file);
        encryptContent(file);
    }

    private static void chown(String file_name, String subject) throws Exception {
        FileObject file = getFile(file_name);
        if (file == null) {
            System.out.println("There is no such a file!");
        } else if (!files.get(0).subjects.contains(subject)) {
            System.out.println("There is no such a subject!");
        } else {
            if (file.owner.equals(currentUser)) {
                file.owner = subject;
                file.readPermission.add(subject);
                file.writePermission.add(subject);
            } else {
                System.out.println("Permission denied!");
            }
        }
        encyptMetaData(file);
    }

    private static void grant_r(String file_name, String subject) throws Exception {
        FileObject file = getFile(file_name);
        if (file == null) {
            System.out.println("There is no such a file!");
        } else if (!files.get(0).subjects.contains(subject)) {
            System.out.println("There is no such a subject!");
        } else {
            if (file.owner.equals(currentUser)) {
                file.readPermission.add(subject);
            } else {
                System.out.println("Permission denied!");
            }
        }
        encyptMetaData(file);
    }

    private static void revoke_r(String file_name, String subject) throws Exception {
        FileObject file = getFile(file_name);
        if (file == null) {
            System.out.println("There is no such a file!");
        } else if (!files.get(0).subjects.contains(subject)) {
            System.out.println("There is no such a subject!");
        } else {
            if (file.owner.equals(currentUser)) {
                if (file.writePermission.contains(subject)) {
                    System.out.println("Violation of safety condition!");
                } else {
                    file.readPermission.remove(subject);
                }
            } else if(!file.owner.equals(currentUser) && currentUser.equals(subject) && !file.writePermission.contains(subject)){
                file.readPermission.remove(subject);
            } else {
                System.out.println("Permission denied!");
            }
        }
        encyptMetaData(file);
    }

    private static void grant_w(String file_name, String subject) throws Exception {
        FileObject file = getFile(file_name);
        if (file == null) {
            System.out.println("There is no such a file!");
        } else if (!files.get(0).subjects.contains(subject)) {
            System.out.println("There is no such a subject!");
        } else if (file.owner.equals(currentUser)) {
            if (!file.readPermission.contains(subject)) {
                System.out.println("Violation of safety condition!");
            } else {
                file.writePermission.add(subject);
            }
        } else {
            System.out.println("Permission denied!");
        }
        encyptMetaData(file);
    }

    private static void revoke_w(String file_name, String subject) throws Exception {
        FileObject file = getFile(file_name);
        if (file == null) {
            System.out.println("There is no such a file!");
        } else if (!files.get(0).subjects.contains(subject)) {
            System.out.println("There is no such a subject!");
        } else {
            if (file.owner.equals(currentUser)) {
                file.writePermission.remove(subject);
            } else if (currentUser.equals(subject)) {
                file.writePermission.remove(subject);
            } else {
                System.out.println("Permission denied!");
            }
        }
        encyptMetaData(file);
    }

    private static void ls() throws Exception {
        decryptAllMetaData();
        for (int i = 1; i < files.size(); i++) {
            if (files.get(i).deleted.equals("f")) {
                if (files.get(i).readPermission.contains(currentUser)) {
                    System.out.print(files.get(i).name + " (");
                    for (int j = 0; j < files.get(i).readPermission.size(); j++) {
                        String o = "";
                        if (files.get(i).owner.equals(files.get(i).readPermission.get(j))) o = "(o)";
                        if (!files.get(i).writePermission.contains(files.get(i).readPermission.get(j))) {
                            System.out.print(" <" + files.get(i).readPermission.get(j) + o + ", (r)>,");
                        } else if (files.get(i).writePermission.contains(files.get(i).readPermission.get(j))) {
                            System.out.print((" <" + files.get(i).readPermission.get(j) + o + ", (r,w)>"));
                        }
                    }
                    System.out.println(" )");
                }
            }
        }
        encryptAllMetaData();
    }

    private static void ls_all() throws Exception {
        decryptAllMetaData();
        for (int i = 1; i < files.size(); i++) {
            if (files.get(i).deleted.equals("f")) {
                System.out.print(files.get(i).name + " (");
                for (int j = 0; j < files.get(i).readPermission.size(); j++) {
                    String o = "";
                    if (files.get(i).owner.equals(files.get(i).readPermission.get(j))) o = "(o)";
                    if (!files.get(i).writePermission.contains(files.get(i).readPermission.get(j))) {
                        System.out.print(" <" + files.get(i).readPermission.get(j) + o + ", (r)>,");
                    } else if (files.get(i).writePermission.contains(files.get(i).readPermission.get(j))) {
                        System.out.print((" <" + files.get(i).readPermission.get(j) + o + ", (r,w)>"));
                    }
                }
                System.out.println(" )");
            }
        }
        encryptAllMetaData();
    }


    private static void reorganize() throws Exception {
        decryptAllMetaData();
        for(int i = 0; i < files.size(); i++) {
            if (files.get(i).deleted.equals("t")) {
                files.remove(files.get(i));
            }
        }
        encryptAllMetaData();
    }

    public static FileObject getFile(String file_name) throws Exception {

        for (int i = 1; i < files.size(); i++) {
            decryptMetaData(files.get(i));
            if (files.get(i).name.equals(file_name)) {
                return files.get(i);
            }
            encyptMetaData(files.get(i));
        }
        return null;
    }

    public static String encrypt (byte[] data, byte[] keyValue, byte[] iv) throws Exception {
        Key key = new SecretKeySpec(keyValue, "AES");
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,key, ivParam);
        byte[] encryptedVal = cipher.doFinal(data);
        String encryptedValue = new BASE64Encoder().encode(encryptedVal);
        return encryptedValue;
    }

    public static  String decrypt (String encryptedValue, byte[] keyValue, byte[] iv) throws Exception {
        Key key = new SecretKeySpec(keyValue, "AES");
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,key, ivParam);
        byte[] decryptedVal = new BASE64Decoder().decodeBuffer(encryptedValue);
        byte[] decryptedValue = cipher.doFinal(decryptedVal);
        String encodedDecVal = new String(decryptedValue);

        return encodedDecVal;
    }

    public static void decryptMetaData (FileObject file) throws Exception {
        file.name = decrypt(file.name, keyValue, file.iv);
        file.owner = decrypt(file.owner, keyValue, file.iv);
        file.deleted = decrypt(file.deleted, keyValue, file.iv);

        for (int i = 0; i < file.readPermission.size(); i++) {
            file.readPermission.set(i,decrypt(file.readPermission.get(i), keyValue, file.iv));
        }

        for (int i = 0; i < file.writePermission.size(); i++) {
            file.writePermission.set(i,decrypt(file.writePermission.get(i), keyValue, file.iv));
        }
    }

    public static void decryptContent (FileObject file) throws Exception {
        file.fileContent  = decrypt(new String(file.fileContent), keyValue, file.iv).getBytes();
    }

    public  static void encyptMetaData (FileObject file) throws Exception {
        file.name = encrypt(file.name.getBytes(), keyValue, file.iv);
        file.owner = encrypt(file.owner.getBytes(), keyValue, file.iv);
        file.deleted = encrypt(file.deleted.getBytes(), keyValue, file.iv);

        for (int i = 0; i < file.readPermission.size(); i++) {
            file.readPermission.set(i,encrypt(file.readPermission.get(i).getBytes(), keyValue, file.iv));
        }

        for (int i = 0; i < file.writePermission.size(); i++) {
            file.writePermission.set(i,encrypt(file.writePermission.get(i).getBytes(), keyValue, file.iv));
        }
    }

    public static void encryptContent (FileObject file) throws Exception {
        file.fileContent = encrypt(file.fileContent, keyValue, file.iv).getBytes();
    }

    public static void decryptAllMetaData() throws Exception {
        for (int i = 1; i < files.size(); i++) {
            decryptMetaData(files.get(i));
        }
    }

    public static  void encryptAllMetaData() throws Exception {
        for (int i = 1; i < files.size(); i++) {
            encyptMetaData(files.get(i));
        }
    }

    public  static void decryptAllContent() throws Exception {
        for (int i = 1; i < files.size(); i++) {
            decryptContent(files.get(i));
        }
    }

    public static void encryptAllContent() throws Exception {
        for (int i = 1; i < files.size(); i++) {
            encryptContent(files.get(i));
        }
    }
}

class MaskingThread extends Thread {
    private volatile boolean stop;

    private char echochar = '*';

    public MaskingThread(String prompt) {
        System.out.print(prompt);
    }

    public void run() {
        int priority = Thread.currentThread().getPriority();
        Thread.currentThread().setPriority(Thread.MAX_PRIORITY);
        try {
            stop = true;
            while (stop) {
                System.out.print("\010" + echochar);
                try {

                    Thread.currentThread().sleep(1);
                } catch (InterruptedException iex) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        } finally {

            Thread.currentThread().setPriority(priority);
        }
    }

    public void stopMasking() {
        this.stop = false;
    }
}

class PasswordField {
        public static final char[] getPassword(InputStream in, String prompt) throws IOException {
            MaskingThread maskingthread = new MaskingThread(prompt);
            Thread thread = new Thread(maskingthread);
            thread.start();
            char[] lineBuffer;
            char[] buf;
            int i;
            buf = lineBuffer = new char[128];
            int room = buf.length;
            int offset = 0;
            int c;
            loop:
            while (true) {
                switch (c = in.read()) {
                    case -1:
                    case '\n':
                        break loop;
                    case '\r':
                        int c2 = in.read();
                        if ((c2 != '\n') && (c2 != -1)) {
                            if (!(in instanceof PushbackInputStream)) {
                                in = new PushbackInputStream(in);
                            }
                            ((PushbackInputStream) in).unread(c2);
                        } else {
                            break loop;
                        }
                    default:
                        if (--room < 0) {
                            buf = new char[offset + 128];
                            room = buf.length - offset - 1;
                            System.arraycopy(lineBuffer, 0, buf, 0, offset);
                            Arrays.fill(lineBuffer, ' ');
                            lineBuffer = buf;
                        }
                        buf[offset++] = (char) c;
                        break;
                }
            }
            maskingthread.stopMasking();
            if (offset == 0) {
                return null;
            }
            char[] ret = new char[offset];
            System.arraycopy(buf, 0, ret, 0, offset);
            Arrays.fill(buf, ' ');
            return ret;
        }
}
