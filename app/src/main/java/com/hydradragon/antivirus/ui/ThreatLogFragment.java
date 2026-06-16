package com.hydradragon.antivirus.ui;

import android.graphics.Color;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ScrollView;
import android.widget.TextView;
import com.hydradragon.antivirus.R;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.hydradragon.antivirus.service.ThreatLogger;

public class ThreatLogFragment extends Fragment {
    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        ScrollView scrollView = new ScrollView(getContext());
        scrollView.setBackgroundColor(Color.parseColor("#0a0a0a"));
        
        TextView tv = new TextView(getContext());
        tv.setText(getString(R.string.threat_logs_title) + "\n\n" + ThreatLogger.getLogs(getContext()));
        tv.setTextColor(Color.parseColor("#00FFFF"));
        tv.setTextSize(14);
        tv.setPadding(40, 40, 40, 40);
        tv.setTypeface(android.graphics.Typeface.MONOSPACE);
        
        scrollView.addView(tv);
        return scrollView;
    }
}
