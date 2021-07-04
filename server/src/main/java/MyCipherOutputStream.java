import lombok.SneakyThrows;

import javax.crypto.Cipher;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

public class MyCipherOutputStream extends OutputStream {
    private final OutputStream out;
    private final Cipher c;
    private final List<Byte> buffer = new ArrayList<>();

    public MyCipherOutputStream(OutputStream out, Cipher c) {
        this.out = out;
        this.c = c;
    }

    @Override
    public void write(int b) {
        buffer.add((byte) b);
    }
    private static byte[] intToBytes( final int i ) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(i);
        return bb.array();
    }
    @SneakyThrows
    @Override
    public void flush()
    {
        int n=buffer.size();
        if (n == 0)
            return;
        out.write(intToBytes(c.getOutputSize(n)));
        byte[] msg = new byte[n];
        for (int i =0;i<n;i++)
            msg[i] = buffer.get(i);
        out.write(c.doFinal(msg));
        out.flush();
        buffer.clear();
    }

    @Override
    public void close() throws IOException {
        flush();
        out.close();
    }

}
