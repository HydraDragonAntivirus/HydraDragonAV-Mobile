package com.hydradragon.antivirus.ui;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.os.Bundle;
import android.text.TextUtils;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;

/**
 * Full-screen HTML "site blocked" page shown INSTEAD of a malicious website
 * (and instead of redirecting the user to the antivirus dashboard). Rendered as
 * a local WebView page — nothing from the malicious site is loaded.
 */
public class BlockActivity extends Activity {

    public static final String EXTRA_URL = "url";
    public static final String EXTRA_CAT = "cat";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        String url = getIntent() != null ? getIntent().getStringExtra(EXTRA_URL) : null;
        String cat = getIntent() != null ? getIntent().getStringExtra(EXTRA_CAT) : null;
        if (url == null) url = "";
        if (cat == null) cat = "Malicious";

        WebView wv = new WebView(this);
        // JS only drives our local "Go Back" button — no remote content is loaded.
        wv.getSettings().setJavaScriptEnabled(true);
        wv.addJavascriptInterface(new Object() {
            @JavascriptInterface
            public void close() { runOnUiThread(BlockActivity.this::finish); }
        }, "Android");
        wv.loadDataWithBaseURL(null, buildHtml(esc(url), esc(cat)), "text/html", "UTF-8", null);
        setContentView(wv);
    }

    @SuppressLint("MissingSuperCall")
    @Override
    public void onBackPressed() {
        finish();   // leaving the block page just closes it (back to wherever)
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    private static String buildHtml(String url, String cat) {
        return "<!DOCTYPE html><html><head><meta name='viewport' content='width=device-width,"
            + "initial-scale=1'><style>"
            + "html,body{margin:0;height:100%;background:#0b0f14;color:#e6edf3;"
            + "font-family:sans-serif;display:flex;align-items:center;justify-content:center}"
            + ".card{max-width:520px;padding:32px;text-align:center}"
            + ".x{font-size:72px;line-height:1}"
            + "h1{color:#ff4757;font-size:24px;margin:16px 0 8px}"
            + ".cat{display:inline-block;background:#ff475722;color:#ff6b81;border-radius:6px;"
            + "padding:4px 10px;font-size:13px;margin-bottom:16px}"
            + ".url{word-break:break-all;background:#161b22;border:1px solid #30363d;"
            + "border-radius:8px;padding:12px;font-family:monospace;font-size:13px;color:#9aa4af}"
            + "p{color:#9aa4af;font-size:14px;line-height:1.5;margin:16px 0 24px}"
            + "button{background:#238636;color:#fff;border:0;border-radius:8px;padding:14px 28px;"
            + "font-size:16px;font-weight:bold}</style></head><body><div class='card'>"
            + "<div class='x'>&#128737;</div>"
            + "<h1>Site Blocked by HydraDragon</h1>"
            + "<div class='cat'>" + cat + "</div>"
            + "<div class='url'>" + (TextUtils.isEmpty(url) ? "(unknown)" : url) + "</div>"
            + "<p>This website was flagged as dangerous (malware / phishing) and was "
            + "blocked to protect you. Nothing from the site was loaded.</p>"
            + "<button onclick='Android.close()'>Go Back</button>"
            + "</div></body></html>";
    }
}
