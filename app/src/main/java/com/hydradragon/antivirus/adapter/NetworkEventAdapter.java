// DOSYA: app/src/main/java/com/hydradragon/antivirus/adapter/NetworkEventAdapter.java
package com.hydradragon.antivirus.adapter;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;

import com.hydradragon.antivirus.R;
import com.hydradragon.antivirus.engine.NetworkMonitor;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * Ağ olayları listesi adapter'ı
 */
public class NetworkEventAdapter extends RecyclerView.Adapter<NetworkEventAdapter.EventViewHolder> {

    private final List<NetworkMonitor.NetworkEvent> events;

    public NetworkEventAdapter(List<NetworkMonitor.NetworkEvent> events) {
        this.events = events;
    }

    @NonNull
    @Override
    public EventViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View v = LayoutInflater.from(parent.getContext())
            .inflate(R.layout.item_network_event, parent, false);
        return new EventViewHolder(v);
    }

    @Override
    public void onBindViewHolder(@NonNull EventViewHolder holder, int position) {
        holder.bind(events.get(position));
    }

    @Override
    public int getItemCount() { return events.size(); }

    static class EventViewHolder extends RecyclerView.ViewHolder {
        TextView tvTime, tvConnection, tvAction, tvReason;

        EventViewHolder(View v) {
            super(v);
            tvTime = v.findViewById(R.id.tv_event_time);
            tvConnection = v.findViewById(R.id.tv_connection);
            tvAction = v.findViewById(R.id.tv_action);
            tvReason = v.findViewById(R.id.tv_event_reason);
        }

        void bind(NetworkMonitor.NetworkEvent event) {
            SimpleDateFormat sdf = new SimpleDateFormat("[HH:mm:ss]", Locale.getDefault());
            tvTime.setText(sdf.format(new Date(event.timestamp)));

            tvConnection.setText(event.destIp + ":" + event.destPort
                + " [" + event.protocol + "]");

            if (event.blocked) {
                tvAction.setText("ENGELLENDİ");
                tvAction.setTextColor(0xFFFF0040);
                itemView.setBackgroundColor(0x15FF0040);
            } else {
                tvAction.setText("İZİN VERİLDİ");
                tvAction.setTextColor(0xFF00FF88);
                itemView.setBackgroundColor(0x00000000);
            }

            tvReason.setText(event.reason);
        }
    }
}
