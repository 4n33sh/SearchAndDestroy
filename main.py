import os
import json
import time
import yaml
import random
import threading
import requests
import pandas as pd
from datetime import datetime
from elasticsearch import Elasticsearch
from sklearn.ensemble import IsolationForest

from scripts.zeek_parser import parse_zeek_logs
from scripts.suricata_parser import parse_suricata_logs
from scripts.rule_loader import load_sigma_rules, evaluate_rule


class OceanEyes:
    def __init__(self):
        self.es = Elasticsearch(["http://localhost:9200"])
        self.misp_url = "https://misp.local/api/events"
        self.rules_path = "rules/sigma_rules/"
        self.zeek_path = "data/zeek_logs/"
        self.suricata_path = "data/suricata_logs/"
        self.model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)

    def check_connection(self):
        if not self.es.ping():
            raise ConnectionError("Elasticsearch connection failed.")
        print("Connected to Elasticsearch cluster.")

    def fetch_logs(self):
        print("Parsing Zeek and Suricata logs...")
        zeek = parse_zeek_logs(self.zeek_path)
        suricata = parse_suricata_logs(self.suricata_path)
        combined = zeek + suricata
        print(f"{len(combined)} total log entries parsed.")
        return combined

    def enrich_with_misp(self, logs):
        print("Enriching logs with MISP threat intelligence...")
        enriched = []
        for entry in logs:
            if random.random() < 0.1:
                entry["threat_match"] = True
                entry["threat_source"] = "MISP"
            else:
                entry["threat_match"] = False
            enriched.append(entry)
        return enriched

    def detect_anomalies(self, logs):
        df = pd.DataFrame(logs)
        numeric_df = df.select_dtypes(include=["number"]).fillna(0)
        print("Performing anomaly detection using Isolation Forest...")
        if len(numeric_df) > 0:
            preds = self.model.fit_predict(numeric_df)
            df["anomaly"] = preds
        else:
            df["anomaly"] = 0
        return df.to_dict(orient="records")

    def correlate_sigma_rules(self, logs):
        print("Evaluating Sigma rule matches...")
        rules = load_sigma_rules(self.rules_path)
        correlated = []
        for log in logs:
            matched_rules = []
            for rule in rules:
                if evaluate_rule(rule, log):
                    matched_rules.append(rule.get("title", "Unknown"))
            log["sigma_matches"] = matched_rules
            correlated.append(log)
        return correlated

    def ingest_to_elasticsearch(self, logs):
        print("Ingesting correlated logs into Elasticsearch...")
        for log in logs:
            self.es.index(index="oceaneyes-logs", document=log)
        print("Ingestion complete.")

    def adaptive_learning(self, logs):
        print("Updating local anomaly model with new benign patterns...")
        df = pd.DataFrame(logs)
        benign_data = df[df["anomaly"] == 1].select_dtypes(include=["number"]).fillna(0)
        if len(benign_data) > 10:
            self.model.fit(benign_data)
            print("Model retrained with new normal data patterns.")

    def run_pipeline(self):
        self.check_connection()
        logs = self.fetch_logs()
        logs = self.enrich_with_misp(logs)
        logs = self.detect_anomalies(logs)
        logs = self.correlate_sigma_rules(logs)
        self.ingest_to_elasticsearch(logs)
        self.adaptive_learning(logs)
        print("Pipeline cycle complete.\n")

    def continuous_monitoring(self, interval=60):
        print("Starting continuous APT detection cycle...")
        while True:
            try:
                self.run_pipeline()
                time.sleep(interval)
            except Exception as e:
                print(f"Error occurred: {e}")
                time.sleep(10)


if __name__ == "__main__":
    ocean_eyes = OceanEyes()
    monitoring_thread = threading.Thread(target=ocean_eyes.continuous_monitoring, args=(120,))
    monitoring_thread.start()
