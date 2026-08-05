package com.hydradragon.antivirus.ui;

import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Bundle;
import android.text.method.LinkMovementMethod;
import android.text.util.Linkify;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;
import com.hydradragon.antivirus.R;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;

import com.hydradragon.antivirus.service.ThreatLogger;

import java.util.ArrayList;
import java.util.List;

public class ThreatLogFragment extends Fragment {

    private LinearLayout containerLogs;
    private String pendingExportBlock = null;

    private final ActivityResultLauncher<String> exportLauncher =
        registerForActivityResult(new ActivityResultContracts.CreateDocument("text/plain"),
            uri -> {
                if (uri == null) return;
                ThreatLogger.exportLogs(requireContext(), uri);
                Toast.makeText(getContext(), R.string.threat_log_exported_toast, Toast.LENGTH_SHORT).show();
            });

    private final ActivityResultLauncher<String> singleExportLauncher =
        registerForActivityResult(new ActivityResultContracts.CreateDocument("text/plain"),
            uri -> {
                if (uri == null || pendingExportBlock == null) return;
                ThreatLogger.exportSingleLog(requireContext(), uri, pendingExportBlock);
                pendingExportBlock = null;
                Toast.makeText(getContext(), R.string.threat_log_exported_toast, Toast.LENGTH_SHORT).show();
            });

    private final ActivityResultLauncher<String[]> importLauncher =
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
        View view = inflater.inflate(R.layout.fragment_threat_log, container, false);

        containerLogs = view.findViewById(R.id.container_logs);

        View btnExport = view.findViewById(R.id.btn_export_logs);
        if (btnExport != null) {
            btnExport.setOnClickListener(v -> exportLauncher.launch("threat_logs.txt"));
        }

        View btnImport = view.findViewById(R.id.btn_import_logs);
        if (btnImport != null) {
            btnImport.setOnClickListener(v -> importLauncher.launch(new String[]{"text/plain"}));
        }

        View btnClear = view.findViewById(R.id.btn_clear_logs);
        if (btnClear != null) {
            btnClear.setOnClickListener(v -> {
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
        }

        refreshLogs();
        return view;
    }

    private void refreshLogs() {
        if (containerLogs == null || getContext() == null) return;
        containerLogs.removeAllViews();

        String rawLogs = ThreatLogger.getLogs(getContext());
        String noLogsText = getString(R.string.no_threat_logs);

        if (rawLogs == null || rawLogs.trim().isEmpty() || rawLogs.trim().equalsIgnoreCase(noLogsText.trim())) {
            renderEmptyState();
            return;
        }

        List<String> entries = parseLogEntries(rawLogs);
        if (entries.isEmpty()) {
            renderEmptyState();
            return;
        }

        for (String entry : entries) {
            renderLogCard(entry);
        }
    }

    private void renderEmptyState() {
        LinearLayout emptyCard = new LinearLayout(getContext());
        emptyCard.setOrientation(LinearLayout.VERTICAL);
        emptyCard.setBackgroundResource(R.drawable.card_background);
        emptyCard.setPadding(48, 48, 48, 48);
        emptyCard.setGravity(android.view.Gravity.CENTER);

        ImageView shieldIcon = new ImageView(getContext());
        shieldIcon.setImageResource(R.drawable.ic_shield_secure);
        shieldIcon.setColorFilter(ContextCompat.getColor(requireContext(), R.color.neon_green));
        LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(96, 96);
        emptyCard.addView(shieldIcon, iconParams);

        TextView title = new TextView(getContext());
        title.setText(R.string.no_threat_logs_title);
        title.setTextColor(ContextCompat.getColor(requireContext(), R.color.text_primary));
        title.setTextSize(16);
        title.setTypeface(Typeface.create("sans-serif-medium", Typeface.BOLD));
        title.setPadding(0, 24, 0, 8);
        emptyCard.addView(title);

        TextView desc = new TextView(getContext());
        desc.setText(R.string.no_threat_logs);
        desc.setTextColor(ContextCompat.getColor(requireContext(), R.color.text_secondary));
        desc.setTextSize(13);
        desc.setGravity(android.view.Gravity.CENTER);
        emptyCard.addView(desc);

        containerLogs.addView(emptyCard);
    }

    private List<String> parseLogEntries(String rawLogs) {
        List<String> list = new ArrayList<>();
        String[] lines = rawLogs.split("\n");
        StringBuilder currentBlock = new StringBuilder();

        for (String line : lines) {
            if (line.trim().startsWith("[") && line.contains("]")) {
                if (currentBlock.length() > 0) {
                    list.add(currentBlock.toString().trim());
                    currentBlock.setLength(0);
                }
            }
            currentBlock.append(line).append("\n");
        }
        if (currentBlock.length() > 0) {
            list.add(currentBlock.toString().trim());
        }
        return list;
    }

    private void renderLogCard(String logBlock) {
        LinearLayout card = new LinearLayout(getContext());
        card.setOrientation(LinearLayout.HORIZONTAL);
        card.setBackgroundResource(R.drawable.card_background);
        card.setPadding(28, 24, 28, 24);

        LinearLayout.LayoutParams cardParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        cardParams.setMargins(0, 0, 0, 20);
        card.setLayoutParams(cardParams);

        // Content on the left
        TextView contentTv = new TextView(getContext());
        contentTv.setText(logBlock);
        contentTv.setTextColor(ContextCompat.getColor(requireContext(), R.color.text_primary));
        contentTv.setTextSize(13);
        contentTv.setLineSpacing(4f, 1.1f);
        contentTv.setTypeface(Typeface.SANS_SERIF);
        contentTv.setAutoLinkMask(Linkify.WEB_URLS);
        contentTv.setMovementMethod(LinkMovementMethod.getInstance());
        contentTv.setLinksClickable(true);

        LinearLayout.LayoutParams textParams = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        card.addView(contentTv, textParams);

        // Action buttons column on the right
        LinearLayout actionCol = new LinearLayout(getContext());
        actionCol.setOrientation(LinearLayout.VERTICAL);
        actionCol.setGravity(android.view.Gravity.TOP | android.view.Gravity.CENTER_HORIZONTAL);
        LinearLayout.LayoutParams colParams = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        colParams.setMargins(16, 0, 0, 0);
        actionCol.setLayoutParams(colParams);

        // Top right: Delete button (Trash icon)
        ImageView btnDelete = new ImageView(getContext());
        btnDelete.setImageResource(R.drawable.ic_trash);
        btnDelete.setColorFilter(ContextCompat.getColor(requireContext(), R.color.threat_red));
        btnDelete.setBackgroundResource(R.drawable.btn_rounded_secondary);
        btnDelete.setPadding(16, 16, 16, 16);
        btnDelete.setClickable(true);
        btnDelete.setFocusable(true);
        btnDelete.setOnClickListener(v -> {
            ThreatLogger.deleteSingleLog(requireContext(), logBlock);
            refreshLogs();
            Toast.makeText(getContext(), R.string.threat_log_cleared_toast, Toast.LENGTH_SHORT).show();
        });

        LinearLayout.LayoutParams btnDelParams = new LinearLayout.LayoutParams(80, 80);
        actionCol.addView(btnDelete, btnDelParams);

        // Bottom right: Export button (Export icon)
        ImageView btnExportSingle = new ImageView(getContext());
        btnExportSingle.setImageResource(R.drawable.ic_export_single);
        btnExportSingle.setColorFilter(ContextCompat.getColor(requireContext(), R.color.neon_cyan));
        btnExportSingle.setBackgroundResource(R.drawable.btn_rounded_secondary);
        btnExportSingle.setPadding(16, 16, 16, 16);
        btnExportSingle.setClickable(true);
        btnExportSingle.setFocusable(true);
        btnExportSingle.setOnClickListener(v -> {
            pendingExportBlock = logBlock;
            singleExportLauncher.launch("threat_entry.txt");
        });

        LinearLayout.LayoutParams btnExpParams = new LinearLayout.LayoutParams(80, 80);
        btnExpParams.setMargins(0, 16, 0, 0);
        actionCol.addView(btnExportSingle, btnExpParams);

        card.addView(actionCol);
        containerLogs.addView(card);
    }
}
