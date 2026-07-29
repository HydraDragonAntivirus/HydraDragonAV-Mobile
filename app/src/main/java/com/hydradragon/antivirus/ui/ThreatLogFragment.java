package com.hydradragon.antivirus.ui;

import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import com.hydradragon.antivirus.R;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.hydradragon.antivirus.service.ThreatLogger;

public class ThreatLogFragment extends Fragment {

    private TextView tv;

    private final androidx.activity.result.ActivityResultLauncher<String> exportLauncher =
        registerForActivityResult(new ActivityResultContracts.CreateDocument("text/plain"),
            uri -> {
                if (uri == null) return;
                ThreatLogger.exportLogs(requireContext(), uri);
                Toast.makeText(getContext(), R.string.threat_log_exported_toast, Toast.LENGTH_SHORT).show();
            });

    private final androidx.activity.result.ActivityResultLauncher<String[]> importLauncher =
        registerForActivityResult(new ActivityResultContracts.OpenDocument(),
            uri -> {
                if (uri == null) return;
                ThreatLogger.importLogs(requireContext(), uri);
                refreshLogs();
                Toast.makeText(getContext(), R.string.threat_log_imported_toast, Toast.LENGTH_SHORT).show();
            });

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        LinearLayout root = new LinearLayout(getContext());
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#0a0a0a"));

        // header row
        LinearLayout header = new LinearLayout(getContext());
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setPadding(40, 40, 40, 20);

        TextView title = new TextView(getContext());
        title.setText(R.string.threat_logs_title);
        title.setTextColor(Color.parseColor("#00FFFF"));
        title.setTextSize(14);
        title.setTypeface(android.graphics.Typeface.MONOSPACE);
        header.addView(title, new LinearLayout.LayoutParams(0, -2, 1));

        TextView exportBtn = new TextView(getContext());
        exportBtn.setText(R.string.threat_log_export);
        exportBtn.setTextColor(Color.parseColor("#FFD700"));
        exportBtn.setTextSize(12);
        exportBtn.setTypeface(android.graphics.Typeface.MONOSPACE);
        exportBtn.setPadding(16, 8, 16, 8);
        exportBtn.setOnClickListener(v -> exportLauncher.launch("threat_logs.txt"));
        header.addView(exportBtn);

        TextView importBtn = new TextView(getContext());
        importBtn.setText(R.string.threat_log_import);
        importBtn.setTextColor(Color.parseColor("#FFD700"));
        importBtn.setTextSize(12);
        importBtn.setTypeface(android.graphics.Typeface.MONOSPACE);
        importBtn.setPadding(16, 8, 16, 8);
        importBtn.setOnClickListener(v -> importLauncher.launch(new String[]{"text/plain"}));
        header.addView(importBtn);

        TextView clearBtn = new TextView(getContext());
        clearBtn.setText(R.string.threat_log_clear);
        clearBtn.setTextColor(Color.parseColor("#FF0040"));
        clearBtn.setTextSize(12);
        clearBtn.setTypeface(android.graphics.Typeface.MONOSPACE);
        clearBtn.setPadding(16, 8, 16, 8);
        clearBtn.setOnClickListener(v -> {
            new android.app.AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setTitle(R.string.threat_log_clear_title)
                .setMessage(R.string.threat_log_clear_msg)
                .setPositiveButton(R.string.threat_log_clear_confirm, (d, w) -> {
                    ThreatLogger.clearLogs(requireContext());
                    refreshLogs();
                    Toast.makeText(getContext(), R.string.threat_log_cleared_toast, Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton(R.string.threat_log_clear_cancel, null)
                .show();
        });
        header.addView(clearBtn);

        root.addView(header);

        ScrollView scrollView = new ScrollView(getContext());
        tv = new TextView(getContext());
        tv.setTextColor(Color.parseColor("#00FFFF"));
        tv.setTextSize(14);
        tv.setPadding(40, 20, 40, 40);
        tv.setTypeface(android.graphics.Typeface.MONOSPACE);
        tv.setAutoLinkMask(android.text.util.Linkify.WEB_URLS);
        tv.setMovementMethod(android.text.method.LinkMovementMethod.getInstance());
        tv.setLinksClickable(true);
        scrollView.addView(tv);
        root.addView(scrollView, new LinearLayout.LayoutParams(-1, -1));

        refreshLogs();
        return root;
    }

    private void refreshLogs() {
        if (tv != null) {
            tv.setText(ThreatLogger.getLogs(getContext()));
        }
    }
}
