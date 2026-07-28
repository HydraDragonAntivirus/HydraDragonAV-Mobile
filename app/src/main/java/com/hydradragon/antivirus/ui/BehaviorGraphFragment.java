package com.hydradragon.antivirus.ui;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import android.widget.Toast;
import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.BehaviorGraphData;
import com.hydradragon.antivirus.engine.BehaviorFlags;
import com.hydradragon.antivirus.views.BehaviorRadarChart;

import java.util.List;
import java.util.Locale;

public class BehaviorGraphFragment extends Fragment {

    private static final String ARG_PACKAGE = "package_name";

    private BehaviorRadarChart radarChart;
    private LinearLayout detailList;
    private TextView tvTitle;

    public static BehaviorGraphFragment newInstance(String packageName) {
        BehaviorGraphFragment f = new BehaviorGraphFragment();
        Bundle args = new Bundle();
        args.putString(ARG_PACKAGE, packageName);
        f.setArguments(args);
        return f;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.fragment_behavior_graph, container, false);
    }

    private Spinner spinnerPackageSelect;
    private final List<String> packageValues = new java.util.ArrayList<>();
    private final List<String> packageLabels = new java.util.ArrayList<>();

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        radarChart = view.findViewById(R.id.radar_chart);
        detailList = view.findViewById(R.id.layout_detail_list);
        tvTitle = view.findViewById(R.id.tv_graph_title);
        spinnerPackageSelect = view.findViewById(R.id.spinner_package_select);

        String initialPkg = getArguments() != null ? getArguments().getString(ARG_PACKAGE, "") : "";

        // Populate package options: General Device Behavior + Per-Package
        packageValues.clear();
        packageLabels.clear();

        packageValues.add("");
        packageLabels.add(getString(R.string.graph_general_device_behavior));

        List<String> observedPkgs = com.hydradragon.antivirus.engine.HipsMonitor.getAllObservedPackages();
        // getAllObservedPackages already strips com.hydradragon.antivirus* — also guard initialPkg.
        if (initialPkg != null && !initialPkg.isEmpty()
                && !initialPkg.startsWith("com.hydradragon.antivirus")
                && !observedPkgs.contains(initialPkg)) {
            observedPkgs.add(0, initialPkg);
        }

        for (String pkg : observedPkgs) {
            packageValues.add(pkg);
            packageLabels.add("📦 " + pkg);
        }

        android.widget.ArrayAdapter<String> adapter = new android.widget.ArrayAdapter<>(
            requireContext(),
            android.R.layout.simple_spinner_item,
            packageLabels
        );
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerPackageSelect.setAdapter(adapter);

        int initialPosition = 0;
        if (initialPkg != null && !initialPkg.isEmpty()) {
            int foundIdx = packageValues.indexOf(initialPkg);
            if (foundIdx >= 0) initialPosition = foundIdx;
        }
        spinnerPackageSelect.setSelection(initialPosition);

        spinnerPackageSelect.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            @Override
            public void onItemSelected(android.widget.AdapterView<?> parent, View v, int position, long id) {
                if (position >= 0 && position < packageValues.size()) {
                    String selectedPkg = packageValues.get(position);
                    tvTitle.setText(selectedPkg.isEmpty()
                        ? getString(R.string.graph_device_behavior)
                        : selectedPkg);
                    loadData(selectedPkg);
                }
            }

            @Override
            public void onNothingSelected(android.widget.AdapterView<?> parent) {}
        });

        loadData(packageValues.get(initialPosition));

        View btnClear = view.findViewById(R.id.btn_clear_behavior_graph);
        btnClear.setOnClickListener(v -> {
            new android.app.AlertDialog.Builder(requireContext(), android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setTitle(R.string.behavior_graph_clear_title)
                .setMessage(R.string.behavior_graph_clear_msg)
                .setPositiveButton(R.string.threat_log_clear_confirm, (d, w) -> {
                    BehaviorFlags.clearAll(requireContext());
                    loadData(spinnerPackageSelect.getSelectedItem().toString());
                    Toast.makeText(getContext(), R.string.behavior_graph_cleared_toast, Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton(R.string.threat_log_clear_cancel, null)
                .show();
        });
    }

    private void loadData(String pkg) {
        BehaviorGraphData data = BehaviorGraphData.forPackage(pkg, getContext());
        List<BehaviorGraphData.AxisValue> axes = data.computeAxisValues();
        radarChart.setData(axes);

        detailList.removeAllViews();
        addDetailItem(getString(R.string.graph_ui_spam), String.valueOf(data.uiSpamCount));
        addDetailItem(getString(R.string.graph_notification_spam), String.valueOf(data.notificationSpamCount));
        addDetailItem(getString(R.string.graph_clickjack), String.valueOf(data.clickjackCount));
        addDetailItem(getString(R.string.graph_ransomware), String.valueOf(data.ransomwareCount));
        addDetailItem(getString(R.string.graph_network), String.valueOf(data.networkConnectionCount));
        addDetailItem(getString(R.string.graph_file_read), String.valueOf(data.fileReadCount));
        addDetailItem(getString(R.string.graph_file_read_high), String.valueOf(data.fileReadHighConfCount));
        addDetailItem(getString(R.string.graph_file_created), String.valueOf(data.fileCreatedCount));
        addDetailItem(getString(R.string.graph_file_copy), String.valueOf(data.fileCopyCount));
        addDetailItem(getString(R.string.graph_miner_memory), data.minerMemoryMb + " MB");
        addDetailItem(getString(R.string.graph_behavior_flags), String.valueOf(data.flagCount));
        addDetailItem(getString(R.string.graph_scan_malware), boolStr(data.hasScanMalware));
        addDetailItem(getString(R.string.graph_strandhogg), boolStr(data.hasStrandHogg));
        addDetailItem(getString(R.string.graph_removal_resistance), boolStr(data.hasRemovalResistance));
        addDetailItem(getString(R.string.graph_launcher_change), boolStr(data.hasLauncherChange));
        addDetailItem(getString(R.string.graph_canary), boolStr(data.hasCanaryTrigger));
        addDetailItem(getString(R.string.graph_device_admin), boolStr(data.isDeviceAdmin));
        addDetailItem(getString(R.string.graph_hidden_app), boolStr(data.isHiddenApp));
        addDetailItem(getString(R.string.graph_observed_files), String.valueOf(data.createdFiles));
        addDetailItem(getString(R.string.graph_deleted_files), String.valueOf(data.deletedFiles));
        addDetailItem(getString(R.string.graph_wiper), boolStr(data.hasWiper));
        addDetailItem(getString(R.string.graph_rooted), boolStr(data.isRooted));
        addDetailItem(getString(R.string.graph_debug), boolStr(data.isDebug));
    }

    private void addDetailItem(String label, String value) {
        Context ctx = getContext();
        if (ctx == null) return;
        LinearLayout row = new LinearLayout(ctx);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setPadding(8, 8, 8, 8);

        TextView tvLabel = new TextView(ctx);
        tvLabel.setText(label + ": ");
        tvLabel.setTextColor(0xFFCCCCCC);
        tvLabel.setTextSize(13f);
        tvLabel.setTypeface(null, android.graphics.Typeface.BOLD);

        TextView tvValue = new TextView(ctx);
        tvValue.setText(value);
        tvValue.setTextColor(0xFF00D4FF);
        tvValue.setTextSize(13f);

        row.addView(tvLabel);
        row.addView(tvValue);
        detailList.addView(row);
    }

    private String boolStr(boolean v) { return getString(v ? R.string.graph_yes : R.string.graph_no); }
}
