package netguardian.dnstest;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

public final class MainActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final AtomicBoolean cancelled = new AtomicBoolean(true);
    private EditText target;
    private TextView status, networkInfo;
    private CheckBox consent, combined;
    private ProgressBar progress;
    private Button start, stop;
    private volatile DatagramSocket socket;
    private volatile Socket tcpSocket;
    private volatile Thread worker;
    private SharedPreferences preferences;
    private boolean running;
    private final Runnable refresh = new Runnable() {
        @Override public void run() { updateControls(); handler.postDelayed(this, 1000); }
    };

    private int dp(int value) { return (int)(value * getResources().getDisplayMetrics().density + 0.5f); }
    private TextView text(LinearLayout parent, String value, int size, int color) {
        TextView view = new TextView(this); view.setText(value); view.setTextSize(size); view.setTextColor(color);
        view.setPadding(0, dp(7), 0, dp(7)); parent.addView(view); return view;
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        preferences = getSharedPreferences("dns-test", MODE_PRIVATE);
        ScrollView scroll = new ScrollView(this);
        LinearLayout content = new LinearLayout(this); content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(dp(24), dp(48), dp(24), dp(32)); content.setBackgroundColor(Color.rgb(11,20,36));
        scroll.setFillViewport(true); scroll.addView(content); setContentView(scroll);
        TextView brand = text(content, "NETGUARDIAN", 14, Color.rgb(34,211,238)); brand.setLetterSpacing(0.18f);
        text(content, "Network alert test", 32, Color.WHITE).setTypeface(null, Typeface.BOLD);
        text(content, "DNS only or combined · local desktop only", 15, Color.rgb(148,163,184));
        text(content, "Test the real capture → detection → alert → risk path using this phone's traffic. Risk reflects distinct indicators; repeating DNS alone does not raise its contribution.", 16, Color.WHITE);
        networkInfo = text(content, "Checking Wi-Fi…", 14, Color.rgb(34,211,238));
        text(content, "NetGuardian desktop IPv4", 15, Color.WHITE);
        target = new EditText(this); target.setSingleLine(true); target.setInputType(InputType.TYPE_CLASS_PHONE);
        target.setTextColor(Color.WHITE); target.setHintTextColor(Color.rgb(148,163,184)); target.setHint("192.168.8.109");
        String suggested = "";
        try { java.io.InputStream in = getAssets().open("desktop-ip.txt"); byte[] bytes = new byte[64]; int n = in.read(bytes); in.close(); if(n>0) suggested = new String(bytes,0,n,"UTF-8").trim(); } catch (Exception ignored) {}
        target.setText(preferences.getString("desktop", suggested)); content.addView(target);
        text(content, "On the desktop, run ipconfig and use its Ethernet IPv4 address. Keep NetGuardian open with Capture: CAPTURING and protection mode DEMO.", 14, Color.rgb(148,163,184));
        consent = new CheckBox(this); consent.setText("This is my NetGuardian desktop, and this phone is connected to my router Wi-Fi Wi-Fi."); consent.setTextColor(Color.WHITE); content.addView(consent);
        combined = new CheckBox(this); combined.setText("Combined high-risk test: TCP checks + bounded traffic + DNS (about 70 seconds)"); combined.setTextColor(Color.WHITE); content.addView(combined);
        text(content, "Combined mode: 12 TCP connection attempts, at most 6,750 small UDP packets at about 150/second for 45 seconds (~20 KB/s payload), then 24 DNS queries. One desktop only. No logins, commands, router targets or internet targets.", 13, Color.rgb(148,163,184));
        start = new Button(this); start.setText("Start 24-query test"); content.addView(start);
        stop = new Button(this); stop.setText("Stop test"); stop.setEnabled(false); content.addView(stop);
        progress = new ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal); progress.setMax(DnsProbe.COUNT); content.addView(progress);
        status = text(content, "Ready. No traffic sent.", 16, Color.WHITE);
        text(content, "WHAT TO CHECK", 13, Color.rgb(34,211,238));
        text(content, "DNS-only: typically 40 for an untrusted phone (20 DNS + 20 identity). Combined: typically 95 (20 DNS + 30 port scan + 25 sustained traffic + 20 identity), or 75 if trusted. Check Threat Detection and Alerts. Capture loss, other indicators and learned baselines can change the result; this app cannot set or guarantee a score.", 15, Color.WHITE);
        text(content, "Allow around 15–30 seconds. Sent does not mean captured: if no alert appears, check the phone's DNS traffic for ngtest- names first. A firewall or capture visibility issue can prevent detection.", 14, Color.rgb(148,163,184));
        text(content, "No router changes. No quarantine. No Wi-Fi reconfiguration. No background service. Stop cancels either test. Switching away stops the test; a one-minute cooldown follows. DNS names end in .invalid.", 13, Color.rgb(148,163,184));
        start.setOnClickListener(v -> review()); stop.setOnClickListener(v -> cancelTest());
    }

    private Network wifi() {
        ConnectivityManager manager = (ConnectivityManager)getSystemService(Context.CONNECTIVITY_SERVICE);
        for (Network network : manager.getAllNetworks()) {
            NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
            if (capabilities != null && capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) return network;
        }
        return null;
    }

    private InetAddress wifiAddress(Network network) {
        ConnectivityManager manager = (ConnectivityManager)getSystemService(Context.CONNECTIVITY_SERVICE);
        LinkProperties properties = manager.getLinkProperties(network);
        if (properties != null) for (LinkAddress link : properties.getLinkAddresses())
            if (link.getAddress() instanceof Inet4Address) return link.getAddress();
        return null;
    }

    private long cooldown() { return Math.max(0, DnsProbe.COOLDOWN_MS-(System.currentTimeMillis()-preferences.getLong("lastRun",0))); }
    private void updateControls() {
        Network network = wifi(); InetAddress address = network == null ? null : wifiAddress(network);
        networkInfo.setText(address == null ? "Wi-Fi IPv4 unavailable. Connect to router Wi-Fi first." : "This phone's Wi-Fi IP: " + address.getHostAddress());
        long wait = cooldown(); start.setEnabled(!running && address != null && wait == 0);
        start.setText(wait > 0 && !running ? "Wait " + ((wait+999)/1000) + "s before another test" : "Start selected test");
        stop.setEnabled(running); target.setEnabled(!running); consent.setEnabled(!running); combined.setEnabled(!running);
    }

    private void review() {
        if (running || cooldown()>0) return;
        final String host = target.getText().toString().trim();
        try {
            byte[] destination = DnsProbe.destination(host);
            Network network = wifi(); InetAddress local = network == null ? null : wifiAddress(network);
            if(local == null || !local.getHostAddress().startsWith("192.168.8.")) throw new IllegalArgumentException("Connect this phone to the 192.168.8.x Wi-Fi network first.");
            if(Arrays.equals(destination,local.getAddress())) throw new IllegalArgumentException("Enter the desktop IP, not this phone's IP.");
            if(!consent.isChecked()) throw new IllegalArgumentException("Confirm that the destination is your NetGuardian desktop.");
            new AlertDialog.Builder(this).setTitle("Start local DNS test?")
                .setMessage(combined.isChecked() ? "Run the combined test against ONLY " + host + "?\n\n12 TCP connection checks (61000–61011), up to 6,750 small UDP packets to port 49053 over about 45 seconds, then 24 DNS queries to port 53. About 70 seconds total.\n\nUse your own desktop with NetGuardian in DEMO. No router changes or physical quarantine. Stop cancels the test." : "Send exactly 24 small DNS queries to " + host + ":53 using Wi-Fi, at one query per second?\n\nNo router changes or quarantine. Keep this screen open. It may produce a DNS anomaly alert on NetGuardian.")
                .setNegativeButton("Cancel", null).setPositiveButton("Start test", (dialog,which)->begin(host)).show();
        } catch (IllegalArgumentException error) { status.setText(error.getMessage()); }
    }

    private void begin(final String host) {
        if(running || cooldown()>0) return;
        final Network network = wifi();
        if(network == null) { status.setText("Wi-Fi disconnected. No traffic sent."); return; }
        running=true; cancelled.set(false); progress.setProgress(0); status.setText("Sending 0 / 24…");
        final boolean highRisk=combined.isChecked();
        preferences.edit().putString("desktop", host).putLong("lastRun",System.currentTimeMillis()).apply(); updateControls();
        worker = new Thread(() -> {
            try (final DatagramSocket outbound = new DatagramSocket()) {
                socket=outbound; network.bindSocket(outbound);
                final String token = UUID.randomUUID().toString().replace("-", "").substring(0,8);
                if(highRisk) {
                    int[] counts=CombinedProbe.run(host,token,(packet,destination,port)-> {
                        if(!cancelled.get())outbound.send(new DatagramPacket(packet,packet.length,InetAddress.getByAddress(destination),port));
                    },(destination,port,timeout)-> {
                        if(cancelled.get())return;
                        try(Socket connection=network.getSocketFactory().createSocket()) {
                            tcpSocket=connection;
                            connection.connect(new InetSocketAddress(InetAddress.getByAddress(destination),port),timeout);
                        } finally { tcpSocket=null; }
                    },new CombinedProbe.Control() {
                        public boolean cancelled(){return cancelled.get();}
                        public long clockMillis(){return android.os.SystemClock.elapsedRealtime();}
                        public void pause(int milliseconds)throws InterruptedException{Thread.sleep(milliseconds);}
                        public void progress(int sent){}
                        public void stage(final String label,final int current,final int total){handler.post(()-> {
                            progress.setProgress(current*DnsProbe.COUNT/total);status.setText(label+": "+current+" / "+total);
                        });}
                    });
                    handler.post(()->status.setText(cancelled.get()?"Stopped. No more traffic will be sent.":"Combined test finished: "+counts[0]+" TCP attempts, "+counts[1]+" traffic samples, "+counts[2]+" DNS queries. Check this phone's evidence and alerts; allow 15–30 seconds for risk evaluation. Expected about 95 only if all indicators were captured and this phone is untrusted."));
                } else {
                int count = DnsProbe.run(host,token,(packet,destination)-> {
                    if(!cancelled.get()) outbound.send(new DatagramPacket(packet,packet.length,InetAddress.getByAddress(destination),DnsProbe.PORT));
                },new DnsProbe.Control() {
                    public boolean cancelled() { return cancelled.get(); }
                    public void progress(final int sent) { handler.post(() -> { progress.setProgress(sent); status.setText("Sent " + sent + " / 24 queries…"); }); }
                    public void pause(int milliseconds) throws InterruptedException { Thread.sleep(milliseconds); }
                });
                handler.post(() -> status.setText(cancelled.get() ? "Stopped. No more queries will be sent." : "Finished: " + count + " queries sent. Check this phone's DNS evidence, alerts and risk score on the desktop."));
                }
            } catch (Exception error) {
                handler.post(() -> status.setText(cancelled.get() ? "Stopped. No more queries will be sent." : "Test stopped: " + error.getClass().getSimpleName() + ". Check Wi-Fi and the desktop IPv4 address. Sent queries do not prove capture or detection."));
            } finally {
                socket=null; worker=null;
                preferences.edit().putLong("lastRun",System.currentTimeMillis()).apply();
                handler.post(() -> { running=false; updateControls(); });
            }
        },"NetGuardianDnsTest"); worker.start();
    }

    private void cancelTest() {
        cancelled.set(true); DatagramSocket active=socket; if(active!=null)active.close();
        Socket activeTcp=tcpSocket; if(activeTcp!=null)try{activeTcp.close();}catch(Exception ignored){}
        Thread activeWorker=worker; if(activeWorker!=null)activeWorker.interrupt();
    }
    @Override protected void onResume() { super.onResume(); handler.post(refresh); }
    @Override protected void onStop() { cancelTest(); handler.removeCallbacks(refresh); super.onStop(); }
    @Override protected void onDestroy() { cancelTest(); handler.removeCallbacksAndMessages(null); super.onDestroy(); }
}
