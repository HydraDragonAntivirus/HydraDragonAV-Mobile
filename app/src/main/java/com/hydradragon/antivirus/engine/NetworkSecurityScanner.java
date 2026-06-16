package com.hydradragon.antivirus.engine;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.util.Log;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;

public class NetworkSecurityScanner {
    private static final String TAG = "HydraDragon-WiFi";
    private final Context context;

    public NetworkSecurityScanner(Context context) { this.context = context; }

    public static class SecurityReport {
        public final boolean isSecure;
        public final String statusMessage;
        public final boolean isArpSpoofing;

        public SecurityReport(boolean isSecure, String statusMessage, boolean isArpSpoofing) {
            this.isSecure = isSecure;
            this.statusMessage = statusMessage;
            this.isArpSpoofing = isArpSpoofing;
        }
    }

    public SecurityReport scanCurrentNetwork() {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm != null) {
            NetworkInfo activeNetwork = cm.getActiveNetworkInfo();
            if (activeNetwork == null || !activeNetwork.isConnected()) return new SecurityReport(true, "No Network Connection", false);
            if (activeNetwork.getType() != ConnectivityManager.TYPE_WIFI) return new SecurityReport(true, "Mobile Data Secure", false);
        }

        WifiManager wifiManager = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wifiManager != null) {
            WifiInfo wifiInfo = wifiManager.getConnectionInfo();
            if (wifiInfo != null) {
                String ssid = wifiInfo.getSSID();
                boolean isArpSpoofed = checkArpSpoofing();
                
                if (isArpSpoofed) return new SecurityReport(false, "CRITICAL: ARP Spoofing (Man-in-the-Middle) Detected!", true);
                else if (ssid.contains("Free") || ssid.contains("Public")) return new SecurityReport(false, "WARNING: Public network. Traffic may be intercepted.", false);
                
                return new SecurityReport(true, "Wi-Fi Network (" + ssid + ") Secure.", false);
            }
        }
        return new SecurityReport(true, "Network Status Unknown", false);
    }

    private boolean checkArpSpoofing() {
        try {
            BufferedReader br = new BufferedReader(new FileReader("/proc/net/arp"));
            String line;
            Map<String, String> macToIpMap = new HashMap<>();
            br.readLine(); 

            while ((line = br.readLine()) != null) {
                String[] parts = line.split(" +");
                if (parts.length >= 4) {
                    String ip = parts[0]; String mac = parts[3];
                    if (mac.matches("..:..:..:..:..:..") && !mac.equals("00:00:00:00:00:00")) {
                        if (macToIpMap.containsKey(mac) && !macToIpMap.get(mac).equals(ip)) {
                            Log.e(TAG, "ARP SPOOFING DETECTED!");
                            br.close(); return true;
                        } else macToIpMap.put(mac, ip);
                    }
                }
            }
            br.close();
        } catch (Exception e) {}
        return false;
    }
}
