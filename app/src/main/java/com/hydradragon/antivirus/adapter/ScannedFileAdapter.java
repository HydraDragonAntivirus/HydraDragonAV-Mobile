package com.hydradragon.antivirus.adapter;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.model.ScannedFileInfo;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class ScannedFileAdapter extends RecyclerView.Adapter<ScannedFileAdapter.ViewHolder> {

    private final List<ScannedFileInfo> files;

    public ScannedFileAdapter(List<ScannedFileInfo> files) {
        this.files = files;
    }

    @NonNull
    @Override
    public ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext())
            .inflate(R.layout.item_scanned_file, parent, false);
        return new ViewHolder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull ViewHolder holder, int position) {
        holder.bind(files.get(position));
    }

    @Override
    public int getItemCount() { return files.size(); }

    static class ViewHolder extends RecyclerView.ViewHolder {
        TextView tvName, tvStatus, tvScore;

        ViewHolder(View v) {
            super(v);
            tvName = v.findViewById(R.id.tv_file_name);
            tvStatus = v.findViewById(R.id.tv_file_status);
            tvScore = v.findViewById(R.id.tv_file_risk);
        }

        void bind(ScannedFileInfo info) {
            String display = info.getAppName() != null && !info.getAppName().isEmpty()
                ? info.getAppName()
                : info.getPackageName() != null && !info.getPackageName().isEmpty()
                    ? info.getPackageName()
                    : info.getFilePath();
            tvName.setText(display);

            if (info.isThreat()) {
                tvStatus.setText(R.string.threat);
                tvStatus.setTextColor(0xFFFF0040);
                tvScore.setText(String.valueOf(info.getRiskScore()));
                tvScore.setTextColor(0xFFFF0040);
            } else {
                tvStatus.setText(R.string.level_clean);
                tvStatus.setTextColor(0xFF00FF88);
                tvScore.setText(String.valueOf(info.getRiskScore()));
                tvScore.setTextColor(0xFF888888);
            }
        }
    }
}
