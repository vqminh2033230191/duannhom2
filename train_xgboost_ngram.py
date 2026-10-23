import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

print("[1/4] Đang đọc file dataset_ngram_features.csv...")
df = pd.read_csv("dataset_ngram_features.csv")

# 1. Xử lý nhãn target (clean -> 0, malware -> 1)
if "label" in df.columns:
    df["target"] = df["label"].apply(
        lambda x: 0 if str(x).strip().lower() == "clean" else 1
    )
elif "target" not in df.columns:
    df["target"] = df.iloc[:, -1].apply(
        lambda x: 0 if str(x).strip().lower() == "clean" else 1
    )

# 2. Lọc danh sách cột đặc trưng (bỏ các cột tên file, nhãn)
ignore_cols = ["file_name", "filename", "label", "target", "md5", "sha256"]
feature_cols = [col for col in df.columns if col not in ignore_cols]

X = df[feature_cols].fillna(0)
y = df["target"]

print(
    f"--> Tổng số mẫu: {len(df)} | Số lượng đặc trưng N-gram: {len(feature_cols)}"
)

# 3. Phân chia tập Train / Test (80:20)
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# 4. Chuẩn hóa dữ liệu với StandardScaler
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("[2/4] Đang huấn luyện XGBoost Classifier trên đặc trưng N-gram...")
model = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=5,
    random_state=42,
    eval_metric="logloss",
)
model.fit(X_train_scaled, y_train)

print("[3/4] Kết quả đánh giá mô hình (XGBoost - N-gram Features):")
y_pred = model.predict(X_test_scaled)
print(f"Độ chính xác (Accuracy): {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("\nBáo cáo chi tiết:\n", classification_report(y_test, y_pred))

print("[4/4] Lưu mô hình N-gram...")
joblib.dump(model, "xgboost_ngram_model.pkl")
joblib.dump(scaler, "scaler_ngram.pkl")

print("\n==================================================")
print(" SẴN SÀNG TÍCH HỢP HỆ THỐNG (N-GRAM)!")
print(" File mô hình: xgboost_ngram_model.pkl")
print(" File chuẩn hóa: scaler_ngram.pkl")
print("==================================================")