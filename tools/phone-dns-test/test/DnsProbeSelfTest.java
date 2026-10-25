package netguardian.dnstest;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public final class DnsProbeSelfTest {
    private static void require(boolean ok, String message) { if(!ok)throw new AssertionError(message); }
    private static final class Control implements DnsProbe.Control {
        int sent, pauses; final int stopAfter;
        Control(int stopAfter) { this.stopAfter=stopAfter; }
        public boolean cancelled() { return sent>=stopAfter; }
        public void progress(int value) { sent=value; }
        public void pause(int milliseconds) { require(milliseconds==1000,"Rate is not one query/second"); pauses++; }
    }
    public static void main(String[] args) throws Exception {
        final List<byte[]> packets=new ArrayList<>();
        Control full=new Control(99);
        int sent=DnsProbe.run("192.168.8.109","0123abcd",(p,a)-> {
            require(Arrays.equals(a,new byte[]{(byte)192,(byte)168,8,109}),"Wrong target");packets.add(p);
        },full);
        require(sent==24 && packets.size()==24 && full.pauses==23,"Finite packet or rate limit failed");
        Control cancelled=new Control(3);
        require(DnsProbe.run("192.168.8.109","0123abcd",(p,a)->{},cancelled)==3,"Cancel failed");
        Control stopped=new Control(0);
        require(DnsProbe.run("192.168.8.109","0123abcd",(p,a)->{throw new AssertionError("Sent after cancel");},stopped)==0,"Pre-cancel failed");
        for(String bad:new String[]{"8.8.8.8","1.1.1.1","example.com","127.0.0.1","192.168.8.1","192.168.8.0","192.168.8.255","192.168.9.10","192.168.8.-1","192.168.8.999"}) {
            try { DnsProbe.destination(bad); throw new AssertionError("Accepted forbidden target: "+bad); }
            catch(IllegalArgumentException expected) {}
        }
        try { DnsProbe.packet(24,"0123abcd");throw new AssertionError("Packet bound ignored"); }catch(IllegalArgumentException expected){}
        require(DnsProbe.PORT==53 && DnsProbe.COOLDOWN_MS==60000L,"Destination or cooldown changed");
        System.out.println("PASS bounded run, fixed target, rate, cancellation, pre-cancel, forbidden targets, packet bounds, cooldown");
        for(byte[] packet:packets)System.out.println(Base64.getEncoder().encodeToString(packet));
    }
}
