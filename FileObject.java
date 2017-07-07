

import java.io.Serializable;
import java.util.ArrayList;


/**
 * Created by barisyagan on 11/16/16.
 */
public class FileObject implements Serializable {

    public byte[] iv = new byte[16];
    public String name = "";
    public String owner = "";
    public ArrayList<String> readPermission = new ArrayList<>();
    public ArrayList<String> writePermission = new ArrayList<>();
    public byte[] fileContent = null;
    public String deleted = "";
    public ArrayList<String> subjects = new ArrayList<>();
    public ArrayList<byte[]> passwords = new ArrayList<>();
    public ArrayList<byte[]> salts = new ArrayList<>();

    public FileObject(String name, String owner, byte[] fileContent, byte[] iv) {
        this.name = name;
        this.owner = owner;
        this.fileContent = fileContent;
        this.iv = iv;
        readPermission.add(owner);
        writePermission.add(owner);
        this.deleted = "f";


    }

    public FileObject(){

    }

}
