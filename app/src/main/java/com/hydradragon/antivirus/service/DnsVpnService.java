package com.hydradragon.antivirus.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.hydradragon.antivirus.engine.UrlThreatScanner;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Local DNS-filtering VPN — MITM-free web protection, the technique mainstream
 * Android AVs use.
 *
 * <p>Only DNS is routed into the tunnel (single /32 + /128 routes to virtual DNS
 * servers); TLS and everything else go out directly and are never seen or
 * decrypted. For each DNS query (IPv4/IPv6, UDP or TCP) we read the hostname
 * (plaintext in the DNS packet), check it against {@link UrlThreatScanner}, then
 * sinkhole malicious ones (NXDOMAIN) or forward clean ones to a real resolver.
 *
 * <p>Scope/limits: IPv4 + IPv6, UDP/53 (robust, stateless) and TCP/53
 * (best-effort: assumes the query arrives in one segment, one query per
 * connection — covers normal resolver behaviour). DoH/DoT (encrypted DNS) is
 * out of scope by design — block those resolver IPs via the blooms if needed.
 */
public class DnsVpnService extends VpnService {

    private static final String TAG = "DnsVpnService";
    private static final String CH_ID = "hydra_webshield";

    private static final String TUN4 = "10.111.222.1";
    private static final String DNS4 = "10.111.222.2";
    private static final String TUN6 = "fd00:0:1110:222::1";
    private static final String DNS6 = "fd00:0:1110:222::2";
    private static final String UPSTREAM = "1.1.1.1";

    private ParcelFileDescriptor vpnInterface;
    private Thread worker;
    private volatile boolean running;
    private ExecutorService forwarders;
    private FileOutputStream tunOut;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (running) return START_STICKY;
        startForegroundShield();
        forwarders = Executors.newCachedThreadPool();
        if (establish()) {
            running = true;
            worker = new Thread(this::loop, "dns-vpn");
            worker.start();
        } else {
            stopSelf();
        }
        return START_STICKY;
    }

    private boolean establish() {
        try {
            Builder b = new Builder()
                .setSession("HydraDragon Web Shield")
                .addAddress(TUN4, 32)
                .addAddress(TUN6, 128)
                .addDnsServer(DNS4)
                .addDnsServer(DNS6)
                .addRoute(DNS4, 32)     // ONLY DNS goes through the tunnel
                .addRoute(DNS6, 128);
            try { b.addDisallowedApplication(getPackageName()); } catch (Exception ignore) {}
            vpnInterface = b.establish();
            return vpnInterface != null;
        } catch (Throwable t) {
            Log.e(TAG, "establish failed", t);
            return false;
        }
    }

    private void loop() {
        try (FileInputStream in = new FileInputStream(vpnInterface.getFileDescriptor())) {
            tunOut = new FileOutputStream(vpnInterface.getFileDescriptor());
            byte[] packet = new byte[32767];
            while (running) {
                int len = in.read(packet);
                if (len <= 0) continue;
                byte[] copy = new byte[len];
                System.arraycopy(packet, 0, copy, 0, len);
                handlePacket(copy, len);
            }
        } catch (Exception e) {
            if (running) Log.w(TAG, "loop ended: " + e.getMessage());
        }
    }

    private synchronized void writeTun(byte[] pkt) {
        try { if (tunOut != null) tunOut.write(pkt); } catch (Exception e) {
            Log.w(TAG, "writeTun: " + e.getMessage());
        }
    }

    // ── IP layer parsing ────────────────────────────────────────────────────

    private void handlePacket(byte[] p, int len) {
        try {
            int version = (p[0] & 0xF0) >> 4;
            int proto, ipHdr, srcOff, dstOff;
            if (version == 4) {
                ipHdr = (p[0] & 0x0F) * 4;
                proto = p[9] & 0xFF;
                srcOff = 12; dstOff = 16;
            } else if (version == 6) {
                ipHdr = 40;
                proto = p[6] & 0xFF;      // next header (no extension headers assumed)
                srcOff = 8; dstOff = 24;
            } else {
                return;
            }
            int trans = ipHdr;
            int dstPort = u16(p, trans + 2);
            if (dstPort != 53) return;

            if (proto == 17) {            // UDP
                handleUdpDns(p, len, version, ipHdr, srcOff, dstOff);
            } else if (proto == 6) {      // TCP
                handleTcpDns(p, len, version, ipHdr, srcOff, dstOff);
            }
        } catch (Exception e) {
            Log.w(TAG, "packet error: " + e.getMessage());
        }
    }

    // ── UDP DNS ─────────────────────────────────────────────────────────────

    private void handleUdpDns(byte[] p, int len, int ver, int ipHdr, int srcOff, int dstOff) {
        int dnsOff = ipHdr + 8;
        String host = parseQName(p, dnsOff, len);
        if (host == null || host.isEmpty()) return;

        String cat = UrlThreatScanner.get(this).scanUrl("http://" + host);
        if (cat != null) {
            byte[] dns = nxdomain(p, dnsOff, len);
            writeTun(buildUdp(p, ver, ipHdr, srcOff, dstOff, dns, dns.length));
            notifyBlocked(host, cat);
            return;
        }
        final byte[] q = slice(p, dnsOff, len - dnsOff);
        forwarders.execute(() -> {
            try (DatagramSocket s = new DatagramSocket()) {
                protect(s);
                s.setSoTimeout(5000);
                InetAddress up = InetAddress.getByName(UPSTREAM);
                s.send(new DatagramPacket(q, q.length, up, 53));
                byte[] ans = new byte[4096];
                DatagramPacket rp = new DatagramPacket(ans, ans.length);
                s.receive(rp);
                byte[] dns = slice(ans, 0, rp.getLength());
                writeTun(buildUdp(p, ver, ipHdr, srcOff, dstOff, dns, dns.length));
            } catch (Exception e) {
                Log.w(TAG, "udp forward: " + e.getMessage());
            }
        });
    }

    // ── TCP DNS (best-effort minimal state machine) ─────────────────────────

    private void handleTcpDns(byte[] p, int len, int ver, int ipHdr, int srcOff, int dstOff) {
        int tcp = ipHdr;
        int flags = p[tcp + 13] & 0xFF;
        long seq = u32(p, tcp + 4);
        int dataOff = ((p[tcp + 12] & 0xF0) >> 4) * 4;
        int payloadOff = tcp + dataOff;
        int payloadLen = len - payloadOff;

        boolean syn = (flags & 0x02) != 0;
        boolean fin = (flags & 0x01) != 0;
        boolean psh = (flags & 0x08) != 0;

        if (syn) {
            // Reply SYN-ACK: our ISN=1000, ack=clientSeq+1.
            long ourSeq = 1000L;
            byte[] r = buildTcp(p, ver, ipHdr, srcOff, dstOff, tcp,
                ourSeq, (seq + 1) & 0xFFFFFFFFL, 0x12 /*SYN,ACK*/, null, 0);
            writeTun(r);
            return;
        }

        if (payloadLen > 2 && (psh || payloadLen > 0)) {
            // TCP DNS payload = 2-byte length prefix + DNS message.
            int dnsLen = u16(p, payloadOff);
            int dnsStart = payloadOff + 2;
            if (dnsStart + dnsLen > len) dnsLen = len - dnsStart;
            String host = parseQName(p, dnsStart, dnsStart + dnsLen);
            long clientNext = (seq + payloadLen) & 0xFFFFFFFFL;   // ack their data
            long ourSeq = 1001L;                                  // after our SYN

            if (host != null && !host.isEmpty()) {
                String cat = UrlThreatScanner.get(this).scanUrl("http://" + host);
                if (cat != null) {
                    byte[] dnsR = nxdomain(p, dnsStart, dnsStart + dnsLen);
                    byte[] framed = frameTcpDns(dnsR);
                    byte[] data = buildTcp(p, ver, ipHdr, srcOff, dstOff, tcp,
                        ourSeq, clientNext, 0x18, framed, framed.length);
                    writeTun(data);
                    byte[] f = buildTcp(p, ver, ipHdr, srcOff, dstOff, tcp,
                        (ourSeq + framed.length) & 0xFFFFFFFFL, clientNext, 0x11, null, 0);
                    writeTun(f);
                    notifyBlocked(host, cat);
                    return;
                }
            }
            final byte[] query = slice(p, payloadOff, payloadLen);   // includes 2-byte length
            final int fVer = ver, fIpHdr = ipHdr, fSrc = srcOff, fDst = dstOff, fTcp = tcp;
            final long fClientNext = clientNext, fOurSeq = 1001L;
            final byte[] fp = p;
            forwarders.execute(() -> {
                try (Socket sk = new Socket()) {
                    protect(sk);
                    sk.connect(new InetSocketAddress(UPSTREAM, 53), 5000);
                    sk.getOutputStream().write(query);
                    sk.getOutputStream().flush();
                    byte[] buf = new byte[8192];
                    int n = sk.getInputStream().read(buf);
                    if (n <= 0) return;
                    byte[] reply = slice(buf, 0, n);                 // already length-prefixed
                    byte[] data = buildTcp(fp, fVer, fIpHdr, fSrc, fDst, fTcp,
                        fOurSeq, fClientNext, 0x18, reply, reply.length);
                    writeTun(data);
                    byte[] fin2 = buildTcp(fp, fVer, fIpHdr, fSrc, fDst, fTcp,
                        (fOurSeq + reply.length) & 0xFFFFFFFFL, fClientNext, 0x11, null, 0);
                    writeTun(fin2);
                } catch (Exception e) {
                    Log.w(TAG, "tcp forward: " + e.getMessage());
                }
            });
            return;
        }

        if (fin) {
            long ourSeq = 1001L;
            byte[] ack = buildTcp(p, ver, ipHdr, srcOff, dstOff, tcp,
                ourSeq, (seq + 1) & 0xFFFFFFFFL, 0x10 /*ACK*/, null, 0);
            writeTun(ack);
        }
    }

    private static byte[] frameTcpDns(byte[] dns) {
        byte[] out = new byte[dns.length + 2];
        out[0] = (byte) ((dns.length >> 8) & 0xFF);
        out[1] = (byte) (dns.length & 0xFF);
        System.arraycopy(dns, 0, out, 2, dns.length);
        return out;
    }

    // ── DNS helpers ─────────────────────────────────────────────────────────

    private static String parseQName(byte[] p, int dnsOff, int end) {
        int i = dnsOff + 12;
        StringBuilder sb = new StringBuilder();
        while (i < end) {
            int l = p[i] & 0xFF;
            if (l == 0) break;
            if ((l & 0xC0) != 0) return null;
            i++;
            if (i + l > end) return null;
            if (sb.length() > 0) sb.append('.');
            for (int k = 0; k < l; k++) sb.append((char) (p[i + k] & 0xFF));
            i += l;
        }
        return sb.toString().toLowerCase();
    }

    private static byte[] nxdomain(byte[] p, int dnsOff, int end) {
        byte[] dns = slice(p, dnsOff, end - dnsOff);
        if (dns.length < 12) return dns;
        dns[2] = (byte) 0x81;   // QR=1, RD copied roughly
        dns[3] = (byte) 0x83;   // RA=1, RCODE=3 NXDOMAIN
        dns[6] = 0; dns[7] = 0; dns[8] = 0; dns[9] = 0; dns[10] = 0; dns[11] = 0;
        return dns;
    }

    // ── Packet builders (IPv4 + IPv6) ───────────────────────────────────────

    /** Build a UDP/53 reply back to the client wrapping a DNS payload. */
    private static byte[] buildUdp(byte[] req, int ver, int ipHdr, int srcOff, int dstOff,
                                   byte[] dns, int dnsLen) {
        int udpLen = 8 + dnsLen;
        int total = ipHdr + udpLen;
        byte[] r = new byte[total];
        System.arraycopy(req, 0, r, 0, ipHdr);
        swapAddrs(r, ver, srcOff, dstOff, req);
        // UDP header: swap ports
        System.arraycopy(req, ipHdr + 2, r, ipHdr, 2);
        System.arraycopy(req, ipHdr, r, ipHdr + 2, 2);
        writeU16(r, ipHdr + 4, udpLen);
        r[ipHdr + 6] = 0; r[ipHdr + 7] = 0;
        System.arraycopy(dns, 0, r, ipHdr + 8, dnsLen);
        finishIp(r, ver, ipHdr, total, 17);
        transportChecksum(r, ver, ipHdr, srcOff, dstOff, 17, udpLen);
        return r;
    }

    /** Build a TCP/53 segment back to the client. */
    private static byte[] buildTcp(byte[] req, int ver, int ipHdr, int srcOff, int dstOff,
                                   int tcp, long seq, long ack, int flags,
                                   byte[] data, int dataLen) {
        int tcpHdr = 20;
        int segLen = tcpHdr + (data != null ? dataLen : 0);
        int total = ipHdr + segLen;
        byte[] r = new byte[total];
        System.arraycopy(req, 0, r, 0, ipHdr);
        swapAddrs(r, ver, srcOff, dstOff, req);
        int t = ipHdr;
        // ports swapped
        System.arraycopy(req, tcp + 2, r, t, 2);
        System.arraycopy(req, tcp, r, t + 2, 2);
        writeU32(r, t + 4, seq);
        writeU32(r, t + 8, ack);
        r[t + 12] = (byte) ((tcpHdr / 4) << 4);    // data offset
        r[t + 13] = (byte) flags;
        writeU16(r, t + 14, 65535);                // window
        r[t + 16] = 0; r[t + 17] = 0;              // checksum (later)
        r[t + 18] = 0; r[t + 19] = 0;              // urgent ptr
        if (data != null && dataLen > 0) System.arraycopy(data, 0, r, t + tcpHdr, dataLen);
        finishIp(r, ver, ipHdr, total, 6);
        transportChecksum(r, ver, ipHdr, srcOff, dstOff, 6, segLen);
        return r;
    }

    private static void swapAddrs(byte[] r, int ver, int srcOff, int dstOff, byte[] req) {
        int n = (ver == 4) ? 4 : 16;
        System.arraycopy(req, dstOff, r, srcOff, n);   // their dst -> our src
        System.arraycopy(req, srcOff, r, dstOff, n);   // their src -> our dst
    }

    /** Fill in IP length + checksum (v4) / payload length (v6). */
    private static void finishIp(byte[] r, int ver, int ipHdr, int total, int proto) {
        if (ver == 4) {
            writeU16(r, 2, total);
            r[8] = 64;                 // TTL
            r[9] = (byte) proto;
            r[10] = 0; r[11] = 0;
            int sum = 0;
            for (int i = 0; i < ipHdr; i += 2) sum += u16(r, i);
            while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
            writeU16(r, 10, ~sum & 0xFFFF);
        } else {
            writeU16(r, 4, total - 40); // payload length
            r[6] = (byte) proto;        // next header
            r[7] = 64;                  // hop limit
        }
    }

    /** Compute UDP/TCP checksum with the proper IPv4/IPv6 pseudo-header. */
    private static void transportChecksum(byte[] r, int ver, int ipHdr, int srcOff,
                                          int dstOff, int proto, int transLen) {
        long sum = 0;
        int addrLen = (ver == 4) ? 4 : 16;
        for (int i = 0; i < addrLen; i += 2) sum += u16(r, srcOff + i);
        for (int i = 0; i < addrLen; i += 2) sum += u16(r, dstOff + i);
        sum += proto;
        sum += transLen;
        for (int i = 0; i < transLen - 1; i += 2) sum += u16(r, ipHdr + i);
        if ((transLen & 1) != 0) sum += (r[ipHdr + transLen - 1] & 0xFF) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        int cs = (int) (~sum & 0xFFFF);
        int csOff = (proto == 17) ? ipHdr + 6 : ipHdr + 16;
        // UDP checksum 0 is illegal on the wire -> use 0xFFFF.
        if (proto == 17 && cs == 0) cs = 0xFFFF;
        writeU16(r, csOff, cs);
    }

    // ── byte utils ──────────────────────────────────────────────────────────

    private static int u16(byte[] b, int o) { return ((b[o] & 0xFF) << 8) | (b[o + 1] & 0xFF); }
    private static long u32(byte[] b, int o) {
        return ((long) (b[o] & 0xFF) << 24) | ((b[o + 1] & 0xFF) << 16)
             | ((b[o + 2] & 0xFF) << 8) | (b[o + 3] & 0xFF);
    }
    private static void writeU16(byte[] b, int o, int v) {
        b[o] = (byte) ((v >> 8) & 0xFF); b[o + 1] = (byte) (v & 0xFF);
    }
    private static void writeU32(byte[] b, int o, long v) {
        b[o] = (byte) ((v >> 24) & 0xFF); b[o + 1] = (byte) ((v >> 16) & 0xFF);
        b[o + 2] = (byte) ((v >> 8) & 0xFF); b[o + 3] = (byte) (v & 0xFF);
    }
    private static byte[] slice(byte[] src, int off, int len) {
        byte[] o = new byte[Math.max(0, len)];
        System.arraycopy(src, off, o, 0, o.length);
        return o;
    }

    // ── lifecycle / notifications ───────────────────────────────────────────

    private void notifyBlocked(String host, String cat) {
        try {
            NotificationManager nm = getSystemService(NotificationManager.class);
            nm.notify(host.hashCode(), new Notification.Builder(this, CH_ID)
                .setContentTitle("Malicious site blocked")
                .setContentText(cat + ": " + host)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .build());
        } catch (Exception ignore) {}
    }

    private void startForegroundShield() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel(
            CH_ID, "Web Shield", NotificationManager.IMPORTANCE_LOW));
        startForeground(0xD0A, new Notification.Builder(this, CH_ID)
            .setContentTitle("HydraDragon Web Shield")
            .setContentText("Filtering DNS for malicious sites")
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .build());
    }

    @Override
    public void onDestroy() {
        running = false;
        if (worker != null) worker.interrupt();
        if (forwarders != null) forwarders.shutdownNow();
        try { if (vpnInterface != null) vpnInterface.close(); } catch (Exception ignore) {}
        super.onDestroy();
    }
}
