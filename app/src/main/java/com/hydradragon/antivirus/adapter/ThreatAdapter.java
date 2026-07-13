package com.hydradragon.antivirus.adapter;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.model.ThreatResult;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

public class ThreatAdapter extends RecyclerView.Adapter<ThreatAdapter.ThreatViewHolder> {

    private final List<ThreatResult> threats;
    private OnThreatClickListener listener;

    public interface OnThreatClickListener {
        void onThreatClick(ThreatResult threat);
        default void onThreatDeleteClick(ThreatResult threat) {}
    }

    public ThreatAdapter(List<ThreatResult> threats) {
        this.threats = threats;
    }

    public void setOnThreatClickListener(OnThreatClickListener listener) {
        this.listener = listener;
    }

    @NonNull
    @Override
    public ThreatViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.item_threat, parent, false);
        return new ThreatViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull ThreatViewHolder holder, int position) {
        ThreatResult threat = threats.get(position);
        holder.tvAppName.setText(threat.getAppName());
        holder.tvPackage.setText(threat.getPackageName() != null ? threat.getPackageName() : threat.getApkPath());
        holder.tvRiskScore.setText(holder.itemView.getContext().getString(R.string.risk_score_format, threat.getRiskScore()));
        
        String time = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
        holder.tvTime.setText(time);

        StringBuilder reasons = new StringBuilder();
        for (String r : threat.getReasons()) {
            reasons.append("► ").append(r).append("\n");
        }
        holder.tvReason.setText(reasons.toString().trim());
        // Make the VirusTotal (and any other) URL tappable.
        android.text.util.Linkify.addLinks(holder.tvReason, android.text.util.Linkify.WEB_URLS);
        holder.tvReason.setMovementMethod(android.text.method.LinkMovementMethod.getInstance());

        // Color Coding
        if (threat.getRiskScore() >= 80) {
            holder.tvThreatLevel.setText(R.string.level_critical);
            holder.tvThreatLevel.setTextColor(0xFFFF0040); // Red
        } else if (threat.getRiskScore() >= 40) {
            holder.tvThreatLevel.setText(R.string.level_medium);
            holder.tvThreatLevel.setTextColor(0xFFFF8800); // Orange
        } else {
            holder.tvThreatLevel.setText(R.string.level_low);
            holder.tvThreatLevel.setTextColor(0xFFFFFF00); // Yellow
        }

        // --- DYNAMIC ICON LOADING SYSTEM ---
        PackageManager pm = holder.itemView.getContext().getPackageManager();
        try {
            Drawable icon = null;
            // If this is a raw .apk file on SD Card, extract the icon from inside it
            if (threat.getApkPath() != null && threat.getApkPath().endsWith(".apk")) {
                PackageInfo pkgInfo = pm.getPackageArchiveInfo(threat.getApkPath(), 0);
                if (pkgInfo != null) {
                    pkgInfo.applicationInfo.sourceDir = threat.getApkPath();
                    pkgInfo.applicationInfo.publicSourceDir = threat.getApkPath();
                    icon = pkgInfo.applicationInfo.loadIcon(pm);
                }
            } else {
                // If it's an app installed on the phone, directly fetch its icon
                icon = pm.getApplicationIcon(threat.getPackageName());
            }
            
            // Display the icon
            if (icon != null) {
                holder.ivAppIcon.setImageDrawable(icon);
            } else {
                // Icon lookup failed (most commonly: the app was already
                // uninstalled after being flagged, so PackageManager no longer
                // has it) — show Android's own generic "unknown app" icon, NOT
                // our dragon logo. Reusing our own branding here read as if the
                // row itself WAS HydraDragon rather than "this app is gone".
                holder.ivAppIcon.setImageResource(android.R.mipmap.sym_def_app_icon);
            }
        } catch (Throwable e) {
            holder.ivAppIcon.setImageResource(android.R.mipmap.sym_def_app_icon);
        }

        // Click event
        holder.itemView.setOnClickListener(v -> {
            if (listener != null) {
                listener.onThreatClick(threat);
            }
        });

        holder.btnDelete.setOnClickListener(v -> {
            if (listener != null) {
                listener.onThreatDeleteClick(threat);
            }
        });
    }

    @Override
    public int getItemCount() {
        return threats.size();
    }

    static class ThreatViewHolder extends RecyclerView.ViewHolder {
        TextView tvAppName, tvThreatLevel, tvPackage, tvReason, tvRiskScore, tvTime;
        ImageView ivAppIcon; // Icon object
        ImageButton btnDelete;

        public ThreatViewHolder(@NonNull View itemView) {
            super(itemView);
            ivAppIcon = itemView.findViewById(R.id.iv_app_icon); // Bind icon
            tvAppName = itemView.findViewById(R.id.tv_app_name);
            tvThreatLevel = itemView.findViewById(R.id.tv_threat_level);
            tvPackage = itemView.findViewById(R.id.tv_package);
            tvReason = itemView.findViewById(R.id.tv_reason);
            tvRiskScore = itemView.findViewById(R.id.tv_risk_score);
            tvTime = itemView.findViewById(R.id.tv_time);
            btnDelete = itemView.findViewById(R.id.btn_delete_threat);
        }
    }
}
