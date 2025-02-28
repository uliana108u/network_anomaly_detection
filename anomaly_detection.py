from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP
import pandas as pd
import time
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import logging


logging.basicConfig(filename="anomaly_report.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")


def process_packet(packet):
    if IP in packet:
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "OTHER"
        data.append({
            "timestamp": time.time(),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": protocol,
            "length": len(packet)
        })


def process_df(data):
    data["timestamp"] = pd.to_datetime(data["timestamp"], unit="s")
    data["length_log"] = np.log1p(data["length"])
    data["protocol_encoded"] = data["protocol"].astype("category").cat.codes

    data.drop(columns=["protocol"], inplace=True)
    return data


def find_anomalies(df):
    print("Detecting anomalies...")
    features = ["length_log", "protocol_encoded"]
    x_test = scaler.transform(df[features])
    df["anomaly"] = model.predict(x_test)
    df["anomaly"] = df["anomaly"].map({1: "normal", -1: "anomaly"})

    # Вывод аномалий
    anomalies = df[df["anomaly"] == "anomaly"]
    print(f"Detected {len(anomalies)} anomalies")
    print(anomalies)

    if not anomalies.empty:
        logging.info(f"Detected {len(anomalies)} anomalies:")
        for _, row in anomalies.iterrows():
            log_message = (f"Anomaly detected - Timestamp: {row['timestamp']}, "
                           f"Src IP: {row['src_ip']}, Dst IP: {row['dst_ip']}, "
                           f"Length: {row['length']}")
            logging.info(log_message)
            print(log_message)


if __name__ == '__main__':
    # Параметры захвата
    duration_default = 86400  # Время сбора (в секундах)
    outfile = "network_traffic.csv"

    data = []

    duration = int(input("Время сбора трафика (в секундах): ")) or duration_default
    flag_trained = input("Использовать ли уже обученную модель (y/n): ") or "y"

    # Захват трафика
    print(f"Capturing network traffic for {duration} seconds...")
    sniff(prn=process_packet, timeout=duration, store=False)

    # Сохранение данных
    print(f"Saving captured traffic to {outfile}")
    df = pd.DataFrame(data)
    df.to_csv(outfile, index=False)

    process_df(df)

    # Загрузка обученной модели или обучение новой
    if flag_trained == "y":
        model, scaler = joblib.load("anomaly_detector_trained.pkl")
        print("Model loaded successfully.")
    elif flag_trained == "n":
        print("Training a new model...")
        modelfile = "anomaly_detector.pkl"
        features = ["length_log", "protocol_encoded"]
        scaler = StandardScaler()
        X = scaler.fit_transform(df[features])
        model = IsolationForest(contamination=0.01, random_state=42)
        model.fit(X)
        joblib.dump((model, scaler), modelfile)
        print(f"New model saved to {modelfile}")

    # Обнаружение аномалий
    find_anomalies(df)











