package de.pterocloud.encryptedconnection;

import java.io.*;
import java.util.Base64;

/**
 * The Packet which is sent over the connection
 */
public class Packet<T> implements Serializable {

    private byte type = (byte) 3;

    private final T object;

    public byte getType() {
        return type;
    }

    public T getObject() {
        return object;
    }

    public Packet(T object) {
        this.object = object;
    }

    public Packet(T object, byte type) {
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

    public static Packet<?> deserialize(byte[] bytes) throws IOException, ClassNotFoundException, ClassCastException {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(Base64.getDecoder().decode(bytes));
        ObjectInputStream dataInput = new ObjectInputStream(inputStream);
        Packet<?> packet = (Packet<?>) dataInput.readObject();
        dataInput.close();
        return packet;
    }

}
