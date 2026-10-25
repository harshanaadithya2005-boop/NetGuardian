package netguardian.dnstest;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** Fixed, finite LAN-only DNS anomaly exercise. No resolver or external service. */
public final class DnsProbe {
    public static final int COUNT = 24;
    public static final int INTERVAL_MS = 1000;
    public static final int PORT = 53;
    public static final long COOLDOWN_MS = 60000L;
    private DnsProbe() {}

    public interface Sink { void send(byte[] packet, byte[] destination) throws IOException; }
    public interface Control {
        boolean cancelled();
        void progress(int sent);
        void pause(int milliseconds) throws InterruptedException;
    }

    public static byte[] destination(String input) {
        String[] parts = input.trim().split("\\.", -1);
        if (parts.length != 4) throw new IllegalArgumentException("Enter the desktop's IPv4 address, such as 192.168.8.109.");
        byte[] address = new byte[4];
        for (int i = 0; i < 4; i++) {
            if (!parts[i].matches("[0-9]{1,3}")) throw new IllegalArgumentException("Use a numeric IPv4 address, not a website.");
            int octet = Integer.parseInt(parts[i]);
            if (octet > 255) throw new IllegalArgumentException("Invalid IPv4 address.");
            address[i] = (byte) octet;
        }
        int host = address[3] & 255;
        if ((address[0] & 255) != 192 || (address[1] & 255) != 168 || (address[2] & 255) != 8 || host < 2 || host > 254)
            throw new IllegalArgumentException("Only the NetGuardian desktop on 192.168.8.2–254 is allowed. Router and internet targets are disabled.");
        return address;
    }

    public static byte[] packet(int number, String runId) throws IOException {
        if (number < 0 || number >= COUNT || !runId.matches("[a-f0-9]{8}")) throw new IllegalArgumentException("Invalid fixed test packet.");
        String name = "ngtest-" + number + "-" + runId + "-abcdefghijklmnopqrstuvwxyz0123456789.invalid";
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bytes);
        out.writeShort(0x4e00 + number); out.writeShort(0x0100);
        out.writeShort(1); out.writeShort(0); out.writeShort(0); out.writeShort(0);
        for (String label : name.split("\\.")) {
            byte[] encoded = label.getBytes(StandardCharsets.US_ASCII);
            out.writeByte(encoded.length); out.write(encoded);
        }
        out.writeByte(0); out.writeShort(1); out.writeShort(1);
        return bytes.toByteArray();
    }

    public static int run(String target, String runId, Sink sink, Control control) throws IOException, InterruptedException {
        byte[] address = destination(target);
        int sent = 0;
        for (int i = 0; i < COUNT && !control.cancelled(); i++) {
            sink.send(packet(i, runId), address); sent++; control.progress(sent);
            if (sent < COUNT && !control.cancelled()) control.pause(INTERVAL_MS);
        }
        return sent;
    }
}
