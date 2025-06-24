import re
import streamlit as st
import matplotlib.pyplot as plt
from collections import defaultdict

st.set_page_config(page_title="Log Analyzer", layout="wide")
st.title("📊 Log File Analyzer")
st.caption("Analyze durations and anomalies in structured event logs")

log_file = st.file_uploader("Upload your debug.txt log file", type="txt")
chart_type = st.selectbox("Chart Type", ["Timeline chart", "Bar chart"])
group_by = st.selectbox("Group by", ["Event type", "Session ID"])
highlight_anomalies = st.checkbox("Highlight anomalies", value=True)
threshold_factor = st.slider("Anomaly threshold (× avg)", 2, 10, 3)
anomaly_min_ms = st.slider("Minimum anomaly duration (ms)", 100, 5000, 500)

if log_file:
    lines = log_file.readlines()
    pattern = re.compile(r"\[(\d+:\d+-[A-F0-9]+)\].*?\((\d+)-(\d+)\s+\[(\d+)\]\)\s+(\w+)\(.*?\):\s+(\d+)\s+ms")

    event_data = []
    event_durations = defaultdict(list)
    session_durations = defaultdict(list)
    thread_ids = set()

    for idx, line in enumerate(lines):
        try:
            line = line.decode("utf-8")
        except:
            continue
        match = pattern.search(line)
        if match:
            thread_id = match[1]
            seq, session, eid, event, duration = int(match[2]), int(match[3]), int(match[4]), match[5], int(match[6])
            thread_ids.add(thread_id)
            event_data.append({
                "idx": idx,
                "thread": thread_id,
                "seq": seq,
                "session": session,
                "event": event,
                "duration": duration
            })
            event_durations[event].append(duration)
            session_durations[session].append(duration)

    if not event_data:
        st.error("No valid entries found in log.")
    else:
        selected_thread = st.selectbox("Filter by Thread ID", sorted(thread_ids))
        filtered = [e for e in event_data if e["thread"] == selected_thread]

        ed = defaultdict(list)
        sd = defaultdict(list)
        for e in filtered:
            ed[e["event"]].append(e["duration"])
            sd[e["session"]].append(e["duration"])
        avg = {k: sum(v)/len(v) for k, v in ed.items()}

        anomalies = []
        if highlight_anomalies:
            for e in filtered:
                if e["duration"] > anomaly_min_ms and e["duration"] > threshold_factor * avg[e["event"]]:
                    anomalies.append(e)

        if chart_type == "Timeline chart":
            fig, ax = plt.subplots(figsize=(14, 6))
            if group_by == "Event type":
                groups = set(e["event"] for e in filtered)
                for g in groups:
                    xs = [e["idx"] for e in filtered if e["event"] == g and e not in anomalies]
                    ys = [e["duration"] for e in filtered if e["event"] == g and e not in anomalies]
                    ax.scatter(xs, ys, label=g, s=10, alpha=0.6)
            else:
                groups = set(e["session"] for e in filtered)
                for g in groups:
                    xs = [e["idx"] for e in filtered if e["session"] == g and e not in anomalies]
                    ys = [e["duration"] for e in filtered if e["session"] == g and e not in anomalies]
                    ax.scatter(xs, ys, label=f"Session {g}", s=10, alpha=0.6)

            if highlight_anomalies and anomalies:
                ax.scatter(
                    [e["idx"] for e in anomalies],
                    [e["duration"] for e in anomalies],
                    color='red', marker='x', s=60, label="Anomaly"
                )

            ax.set_title(f"Timeline (Thread: {selected_thread})")
            ax.set_xlabel("Log Entry Index")
            ax.set_ylabel("Duration (ms)")
            ax.grid(True)
            ax.legend(fontsize="small", loc="upper right")
            st.pyplot(fig)

        else:
            if group_by == "Event type":
                totals = {k: sum(v) for k, v in ed.items()}
            else:
                totals = {k: sum(v) for k, v in sd.items()}

            top = sorted(totals.items(), key=lambda x: x[1], reverse=True)[:10]
            labels = [str(k) for k, _ in top]
            values = [v for _, v in top]

            fig, ax = plt.subplots(figsize=(10, 6))
            ax.barh(labels, values, color='seagreen')
            ax.set_title("Top 10 Slowest by " + ("Event Type" if group_by == "Event type" else "Session ID"))
            ax.set_xlabel("Total Duration (ms)")
            ax.invert_yaxis()
            st.pyplot(fig)

        if highlight_anomalies and anomalies:
            st.subheader("🚨 Detected Anomalies")
            st.dataframe([{
                "Index": e["idx"],
                "Event": e["event"],
                "Session": e["session"],
                "Duration (ms)": e["duration"]
            } for e in anomalies])

        # Summary Section
        st.subheader("📋 Event Duration Summary")
        sort_by = st.selectbox("Sort by", ["Total", "Average", "Max", "Count"])
        sort_key = {
            "Total": lambda x: x["Total Duration (ms)"],
            "Average": lambda x: x["Avg Duration (ms)"],
            "Max": lambda x: x["Max Duration (ms)"],
            "Count": lambda x: x["Count"]
        }[sort_by]

        summary = []
        for event, durations in ed.items():
            total = sum(durations)
            count = len(durations)
            avg_d = total / count
            max_dur = max(durations)
            summary.append({
                "Event": event,
                "Count": count,
                "Total Duration (ms)": total,
                "Avg Duration (ms)": round(avg_d, 2),
                "Max Duration (ms)": max_dur
            })

        summary_sorted = sorted(summary, key=sort_key, reverse=True)
        st.dataframe(summary_sorted)

        if st.checkbox("Show chart for summary"):
            metric = st.selectbox("Chart metric", ["Total Duration (ms)", "Avg Duration (ms)", "Max Duration (ms)"])
            top_n = st.slider("Number of event types to show", 5, 30, 10)
            chart_data = summary_sorted[:top_n]
            labels = [row["Event"] for row in chart_data]
            values = [row[metric] for row in chart_data]
            fig, ax = plt.subplots(figsize=(10, 5))
            ax.barh(labels, values, color="skyblue")
            ax.set_title(f"Top {top_n} Events by {metric}")
            ax.set_xlabel(metric)
            ax.invert_yaxis()
            st.pyplot(fig)
