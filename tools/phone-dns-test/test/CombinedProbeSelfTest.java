package netguardian.dnstest;
import java.util.ArrayList;
import java.util.List;
import java.util.Base64;
import java.util.Arrays;

public final class CombinedProbeSelfTest {
    static void require(boolean ok,String reason){if(!ok)throw new AssertionError(reason);}
    static final class Control implements CombinedProbe.Control {
        long now;int load,dns,tcp;final int stopAfter;final List<String> events=new ArrayList<>();
        Control(int stopAfter){this.stopAfter=stopAfter;}
        public long clockMillis(){return now;}
        public boolean cancelled(){return load>=stopAfter;}
        public void pause(int milliseconds){require(milliseconds==100||milliseconds==1000,"Unexpected rate");now+=milliseconds;}
        public void progress(int sent){}
        public void stage(String label,int current,int total){}
        void send(byte[] packet,byte[] destination,int port){
            require(Arrays.equals(destination,new byte[]{(byte)192,(byte)168,8,109}),"Target changed");
            if(port==CombinedProbe.LOAD_PORT){require(packet.length==128,"Payload cap changed");load++;events.add("E|"+now+"|UDP|"+port+"|128");}
            else{require(port==53,"Unexpected UDP destination");dns++;events.add("E|"+now+"|DNS|53|"+Base64.getEncoder().encodeToString(packet));}
        }
        void connect(byte[] address,int port,int timeout){
            require(port==CombinedProbe.TCP_FIRST+tcp,"Port not in exact 12-port sequence");
            require(timeout==150,"Unbounded TCP timeout");tcp++;events.add("E|"+now+"|TCP|"+port+"|S");
        }
    }
    public static void main(String[] args)throws Exception{
        Control full=new Control(Integer.MAX_VALUE);
        int[] result=CombinedProbe.run("192.168.8.109","0123abcd",full::send,full::connect,full);
        require(Arrays.equals(result,new int[]{12,6750,24}),"Combined traffic bounds failed");
        require(full.now==68000,"Unexpected logical test duration");
        Control cancelled=new Control(17);
        int[] partial=CombinedProbe.run("192.168.8.109","0123abcd",cancelled::send,cancelled::connect,cancelled);
        require(partial[1]==17&&partial[2]==0,"Cancel allowed extra traffic or DNS");
        Control stopped=new Control(0);
        require(Arrays.equals(CombinedProbe.run("192.168.8.109","0123abcd",stopped::send,stopped::connect,stopped),new int[]{0,0,0}),"Pre-cancel failed");
        Control unsafe=new Control(Integer.MAX_VALUE);
        try{CombinedProbe.run("192.168.8.1","0123abcd",unsafe::send,unsafe::connect,unsafe);throw new AssertionError("Router accepted");}
        catch(IllegalArgumentException expected){}
        require(unsafe.events.isEmpty(),"Unsafe target emitted traffic");
        System.out.println("PASS combined bounds, destination, rates, TCP timeout, cancellation, pre-cancel and router rejection");
        for(String event:full.events)System.out.println(event);
    }
}
