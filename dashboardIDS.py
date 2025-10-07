#!/usr/bin/env python3
import json, pathlib, time, streamlit as st, pandas as pd
from streamlit_autorefresh import st_autorefresh

LOG = pathlib.Path("alerts.log")

st.set_page_config("Host IDS Dashboard", layout="wide")
st.title("Host IDS — Live Alerts")

# ── one-click purge ────────────────────────────────────────────
if st.button("🧹 Clear log"):
    LOG.write_text("")              # truncate the file
    st.success("Log cleared.")
    st.experimental_rerun()         # immediately refresh screen

# ── auto-refresh every 3 s ─────────────────────────────────────
st_autorefresh(interval=3_000, key="refresh")

# ── pull latest 500 records ────────────────────────────────────
if not LOG.exists():
    st.warning("alerts.log not found")
    st.stop()

lines   = LOG.read_text().splitlines()[-500:]
records = [json.loads(l) for l in lines]

if not records:
    st.info("No alerts yet")
    st.stop()

df = (pd.DataFrame(records)
        .drop(columns=["ts"], errors="ignore")
        .sort_values("iso_time", ascending=False))

st.metric("Total alerts", len(lines))
st.dataframe(df, use_container_width=True, height=650)
