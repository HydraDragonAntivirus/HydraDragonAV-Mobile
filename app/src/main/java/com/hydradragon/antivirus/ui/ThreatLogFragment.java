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
                Toast.makeText(getContext(), "Threat logs exported", Toast.LENGTH_SHORT).show();
            });

    private final androidx.activity.result.ActivityResultLauncher<String[]> importLauncher =
        registerForActivityResult(new ActivityResultContracts.OpenDocument(),
            uri -> {
                if (uri == null) return;
                ThreatLogger.importLogs(requireContext(), uri);
                refreshLogs();
                Toast.makeText(getContext(), "Threat logs imported", Toast.LENGTH_SHORT).show();
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
        exportBtn.setText("EXPORT .TXT");
        exportBtn.setTextColor(Color.parseColor("#FFD700"));
        exportBtn.setTextSize(12);
        exportBtn.setTypeface(android.graphics.Typeface.MONOSPACE);
        exportBtn.setPadding(16, 8, 16, 8);
        exportBtn.setOnClickListener(v -> exportLauncher.launch("threat_logs.txt"));
        header.addView(exportBtn);

        TextView importBtn = new TextView(getContext());
        importBtn.setText("IMPORT .TXT");
        importBtn.setTextColor(Color.parseColor("#FFD700"));
        importBtn.setTextSize(12);
        importBtn.setTypeface(android.graphics.Typeface.MONOSPACE);
        importBtn.setPadding(16, 8, 16, 8);
        importBtn.setOnClickListener(v -> importLauncher.launch(new String[]{"text/plain"}));
        header.addView(importBtn);

        root.addView(header);

        ScrollView scrollView = new ScrollView(getContext());
        tv = new TextView(getContext());
        tv.setTextColor(Color.parseColor("#00FFFF"));
        tv.setTextSize(14);
        tv.setPadding(40, 20, 40, 40);
        tv.setTypeface(android.graphics.Typeface.MONOSPACE);
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
