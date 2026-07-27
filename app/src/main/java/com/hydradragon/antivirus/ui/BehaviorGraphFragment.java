package com.hydradragon.antivirus.ui;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.BehaviorGraphData;
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

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        radarChart = view.findViewById(R.id.radar_chart);
        detailList = view.findViewById(R.id.layout_detail_list);
        tvTitle = view.findViewById(R.id.tv_graph_title);

        String pkg = getArguments() != null ? getArguments().getString(ARG_PACKAGE, "") : "";
        tvTitle.setText(pkg.isEmpty() ? getString(R.string.graph_device_behavior) : pkg);

        loadData(pkg);
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

    private static String boolStr(boolean v) { return v ? "YES" : "no"; }
}
