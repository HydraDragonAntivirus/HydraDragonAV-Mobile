package com.hydradragon.antivirus.adapter;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.graphics.drawable.Drawable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
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
        holder.tvRiskScore.setText("Risk: " + threat.getRiskScore() + "/100");
        
        String time = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
        holder.tvTime.setText(time);

        StringBuilder reasons = new StringBuilder();
        for (String r : threat.getReasons()) {
            reasons.append("► ").append(r).append("\n");
        }
        holder.tvReason.setText(reasons.toString().trim());

        // Renk Kodlaması
        if (threat.getRiskScore() >= 80) {
            holder.tvThreatLevel.setText("KRİTİK");
            holder.tvThreatLevel.setTextColor(0xFFFF0040); // Kırmızı
        } else if (threat.getRiskScore() >= 40) {
            holder.tvThreatLevel.setText("ORTA");
            holder.tvThreatLevel.setTextColor(0xFFFF8800); // Turuncu
        } else {
            holder.tvThreatLevel.setText("DÜŞÜK");
            holder.tvThreatLevel.setTextColor(0xFFFFFF00); // Sarı
        }

        // --- DİNAMİK İKON YÜKLEME SİSTEMİ ---
        PackageManager pm = holder.itemView.getContext().getPackageManager();
        try {
            Drawable icon = null;
            // Eğer bu SD Karttaki ham bir .apk dosyasıysa ikonunu içinden çekip çıkar
            if (threat.getApkPath() != null && threat.getApkPath().endsWith(".apk")) {
                PackageInfo pkgInfo = pm.getPackageArchiveInfo(threat.getApkPath(), 0);
                if (pkgInfo != null) {
                    pkgInfo.applicationInfo.sourceDir = threat.getApkPath();
                    pkgInfo.applicationInfo.publicSourceDir = threat.getApkPath();
                    icon = pkgInfo.applicationInfo.loadIcon(pm);
                }
            } else {
                // Eğer telefona kurulu bir uygulamaysa doğrudan ikonunu getir
                icon = pm.getApplicationIcon(threat.getPackageName());
            }
            
            // İkonu ekrana bas
            if (icon != null) {
                holder.ivAppIcon.setImageDrawable(icon);
            } else {
                holder.ivAppIcon.setImageResource(R.mipmap.ic_launcher); // Varsayılan Ejderha Logosu
            }
        } catch (Exception e) {
            holder.ivAppIcon.setImageResource(R.mipmap.ic_launcher); // Hata olursa ejderha logosu koy
        }

        // Tıklama olayı
        holder.itemView.setOnClickListener(v -> {
            if (listener != null) {
                listener.onThreatClick(threat);
            }
        });
    }

    @Override
    public int getItemCount() {
        return threats.size();
    }

    static class ThreatViewHolder extends RecyclerView.ViewHolder {
        TextView tvAppName, tvThreatLevel, tvPackage, tvReason, tvRiskScore, tvTime;
        ImageView ivAppIcon; // İkon nesnesi

        public ThreatViewHolder(@NonNull View itemView) {
            super(itemView);
            ivAppIcon = itemView.findViewById(R.id.iv_app_icon); // İkonu bağla
            tvAppName = itemView.findViewById(R.id.tv_app_name);
            tvThreatLevel = itemView.findViewById(R.id.tv_threat_level);
            tvPackage = itemView.findViewById(R.id.tv_package);
            tvReason = itemView.findViewById(R.id.tv_reason);
            tvRiskScore = itemView.findViewById(R.id.tv_risk_score);
            tvTime = itemView.findViewById(R.id.tv_time);
        }
    }
}
