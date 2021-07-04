import lombok.SneakyThrows;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.Queue;

public class MyCipherInputStream extends InputStream {

    private final InputStream in;
    private final Cipher c;
    private final Queue<Byte> buffer = new LinkedList<>();

    public MyCipherInputStream(InputStream in, Cipher c) {
        this.in = in;
        this.c = c;
    }

    @SneakyThrows
    @Override
    public int read() {
        if (buffer.isEmpty())
            fillBuffer();
        return buffer.remove();
    }

    private void fillBuffer() throws IOException, IllegalBlockSizeException, BadPaddingException {
        byte[] sizeInBytes = new byte[4];
        in.read(sizeInBytes);
        int size = ByteBuffer.wrap(sizeInBytes).getInt();
        byte[] data = new byte[size];
        in.read(data);
        data = c.doFinal(data);
        for (int i = 0; i < data.length; i++)
            buffer.add(data[i]);
    }
}
