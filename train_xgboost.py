import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

print("[1/5] Đang đọc file dataset_pe.csv...")
df = pd.read_csv("dataset_pe.csv")

# 1. Xử lý nhãn target (chuyển chữ 'clean' -> 0, 'malware' / các giá trị khác -> 1)
def parse_label(val):
    if str(val).strip().lower() == "clean":
        return 0
    return 1


df["target"] = df["label"].apply(parse_label)

# 2. Danh sách các cột đặc trưng PE Header
feature_cols = [
    "num_sections",
    "max_section_entropy",
    "avg_section_entropy",
    "num_imports",
    "num_suspicious_apis",
    "entry_point",
    "image_size",
    "machine",
    "timestamp",
    "is_dll",
]

available_cols = [col for col in feature_cols if col in df.columns]


# 3. Hàm ép kiểu an toàn cho các đặc trưng (chuyển '0x1ef0' -> số float)
def parse_number(val):
    if pd.isna(val):
        return 0.0
    if isinstance(val, (int, float)):
        return float(val)
    val_str = str(val).strip()
    try:
        if val_str.startswith(("0x", "0X")):
            return float(int(val_str, 16))
        return float(val_str)
    except:
        return 0.0


X = df[available_cols].copy()
for col in available_cols:
    X[col] = X[col].apply(parse_number)

y = df["target"]

# Chia tập dữ liệu Train/Test
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Chuẩn hóa dữ liệu với StandardScaler
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("[2/5] Đang thực hiện PCA và K-Means...")
pca = PCA(n_components=2)
X_train_pca = pca.fit_transform(X_train_scaled)

kmeans = KMeans(n_clusters=2, random_state=42, n_init=10)
cluster_labels = kmeans.fit_predict(X_train_pca)

plt.figure(figsize=(9, 6))
sns.scatterplot(
    x=X_train_pca[:, 0],
    y=X_train_pca[:, 1],
    hue=cluster_labels,
    palette="viridis",
    style=y_train,
    alpha=0.8,
)
plt.title("Trực quan hóa Phân cụm K-Means & PCA 2D trên PE Header")
plt.xlabel("PC1")
plt.ylabel("PC2")
plt.savefig("kmeans_pca_visualization.png", dpi=300)
plt.close()

print("[3/5] Đang huấn luyện XGBoost...")
model = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=5,
    random_state=42,
    eval_metric="logloss",
)
model.fit(X_train_scaled, y_train)

print("[4/5] Kết quả đánh giá mô hình:")
y_pred = model.predict(X_test_scaled)
print(f"Độ chính xác (Accuracy): {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("\nBáo cáo chi tiết:\n", classification_report(y_test, y_pred))

print("[5/5] Lưu file mô hình...")
joblib.dump(model, "xgboost_pe_model.pkl")
joblib.dump(scaler, "scaler.pkl")

print("\n==================================================")
print(" SẴN SÀNG TÍCH HỢP HỆ THỐNG!")
print(" Mô hình XGBoost & Scaler đã được xuất thành công.")
print(" File mô hình: xgboost_pe_model.pkl")
print(" File chuẩn hóa: scaler.pkl")
print("==================================================")