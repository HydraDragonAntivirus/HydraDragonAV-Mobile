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
        tvTitle.setText(pkg.isEmpty() ? "Device Behavior" : pkg);

        loadData(pkg);
    }

    private void loadData(String pkg) {
        BehaviorGraphData data = BehaviorGraphData.forPackage(pkg, getContext());
        List<BehaviorGraphData.AxisValue> axes = data.computeAxisValues();
        radarChart.setData(axes);

        detailList.removeAllViews();
        addDetailItem("UI Spam Events", String.valueOf(data.uiSpamCount));
        addDetailItem("Notification Spam", String.valueOf(data.notificationSpamCount));
        addDetailItem("Ransomware Events", String.valueOf(data.ransomwareCount));
        addDetailItem("Network Connections", String.valueOf(data.networkConnectionCount));
        addDetailItem("File Read Estimates", String.valueOf(data.fileReadCount));
        addDetailItem("High Confidence Reads", String.valueOf(data.fileReadHighConfCount));
        addDetailItem("Miner Memory", data.minerMemoryMb + " MB");
        addDetailItem("Behavior Flags", String.valueOf(data.flagCount));
        addDetailItem("StrandHogg", boolStr(data.hasStrandHogg));
        addDetailItem("Removal Resistance", boolStr(data.hasRemovalResistance));
        addDetailItem("Launcher Change", boolStr(data.hasLauncherChange));
        addDetailItem("Canary Triggered", boolStr(data.hasCanaryTrigger));
        addDetailItem("Device Admin", boolStr(data.isDeviceAdmin));
        addDetailItem("Hidden App", boolStr(data.isHiddenApp));
        addDetailItem("Observed Files", String.valueOf(data.createdFiles));
        addDetailItem("Deleted Files", String.valueOf(data.deletedFiles));
        addDetailItem("Wiper Detected", boolStr(data.hasWiper));
        addDetailItem("Rooted", boolStr(data.isRooted));
        addDetailItem("Debug Mode", boolStr(data.isDebug));
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
