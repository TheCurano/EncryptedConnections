package de.pterocloud.encryptedconnection;

import java.io.*;
import java.util.Base64;

/**
 * The Packet which will be transfered.
 */
public class Packet implements Serializable {

    private byte type = (byte) 3;

    private final Object object;

    public byte getType() {
        return type;
    }

    public Object getObject() {
        return object;
    }

    public Packet(Object object) {
        this.object = object;
    }

    public Packet(Object object, byte type) {
        this.object = object;
        this.type = type;
    }

    public byte[] serialize() throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        ObjectOutputStream dataOutput = new ObjectOutputStream(outputStream);
        dataOutput.writeObject(this);
        dataOutput.close();
        return Base64.getEncoder().encode(outputStream.toByteArray());
    }

    public static Packet deserialize(byte[] bytes) throws IOException, ClassNotFoundException, ClassCastException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(bytes));
        ObjectInputStream dataInput = new ObjectInputStream(inputStream);
        Packet packet = (Packet) dataInput.readObject();
        dataInput.close();
        return packet;
    }

}
