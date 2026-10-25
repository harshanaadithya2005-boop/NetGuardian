package netguardian.dnstest;

import java.io.IOException;

/** Explicit opt-in, bounded test of three independent detectors on one desktop. */
public final class CombinedProbe {
    public static final int TCP_FIRST = 61000;
    public static final int TCP_COUNT = 12;
    public static final int TCP_TIMEOUT_MS = 150;
    public static final int LOAD_PORT = 49053;
    public static final int BATCH_SIZE = 15;
    public static final int TICKS = 450;
    public static final int TICK_MS = 100;
    public static final int LOAD_MAX = BATCH_SIZE * TICKS;
    public static final int PAYLOAD_BYTES = 128;
    private CombinedProbe() {}
    public interface Sink { void send(byte[] packet, byte[] destination, int port) throws IOException; }
    public interface Connector { void attempt(byte[] destination, int port, int timeout) throws IOException; }
    public interface Control extends DnsProbe.Control {
        long clockMillis();
        void stage(String label, int current, int total);
    }
    public static int[] run(String target, String runId, Sink sink, Connector connector, Control control) throws IOException, InterruptedException {
        final byte[] address = DnsProbe.destination(target);
        int connections=0, load=0, dns=0;
        for(int i=0;i<TCP_COUNT && !control.cancelled();i++) {
            try { connector.attempt(address,TCP_FIRST+i,TCP_TIMEOUT_MS); }
            catch(IOException expected) { /* Closed or filtered test ports are normal. No application data is sent. */ }
            connections++; control.stage("TCP connection checks",connections,TCP_COUNT);
        }
        byte[] payload=new byte[PAYLOAD_BYTES];
        byte[] label="NetGuardian controlled LAN test; no commands or credentials".getBytes("US-ASCII");
        System.arraycopy(label,0,payload,0,label.length);
        long start=control.clockMillis();
        for(int tick=0;tick<TICKS && !control.cancelled() && control.clockMillis()-start<60000;tick++) {
            for(int n=0;n<BATCH_SIZE && !control.cancelled();n++) {
                sink.send(payload,address,LOAD_PORT);load++;
            }
            if(tick%10==0)control.stage("Bounded traffic sample",load,LOAD_MAX);
            if(!control.cancelled())control.pause(TICK_MS);
        }
        if(!control.cancelled()) {
            dns=DnsProbe.run(target,runId,(packet,destination)->sink.send(packet,destination,DnsProbe.PORT),new DnsProbe.Control() {
                public boolean cancelled(){return control.cancelled();}
                public void pause(int milliseconds)throws InterruptedException{control.pause(milliseconds);}
                public void progress(int sent){control.stage("DNS queries",sent,DnsProbe.COUNT);}
            });
        }
        return new int[]{connections,load,dns};
    }
}
