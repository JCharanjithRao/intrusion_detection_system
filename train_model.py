import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os

# Column names for NSL-KDD dataset
columns = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes',
    'land','wrong_fragment','urgent','hot','num_failed_logins','logged_in',
    'num_compromised','root_shell','su_attempted','num_root','num_file_creations',
    'num_shells','num_access_files','num_outbound_cmds','is_host_login',
    'is_guest_login','count','srv_count','serror_rate','srv_serror_rate',
    'rerror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate',
    'srv_diff_host_rate','dst_host_count','dst_host_srv_count',
    'dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate','dst_host_serror_rate','dst_host_srv_serror_rate',
    'dst_host_rerror_rate','dst_host_srv_rerror_rate','label','difficulty'
]

print("Loading dataset...")
df = pd.read_csv('dataset/train_data.csv', names=columns)

# 🔥 Convert labels → binary (IMPORTANT FIX)
df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

print(f"Dataset loaded! Total records: {len(df)}")
print(f"Attack records: {len(df[df['label']==1])}")
print(f"Normal records: {len(df[df['label']==0])}")

# 🔥 ONLY KEEP REQUIRED FEATURES (BIG FIX)
df = df[['src_bytes', 'dst_bytes', 'label']]

# Rename for clarity (optional but clean)
df.rename(columns={
    'src_bytes': 'bytes_sent',
    'dst_bytes': 'bytes_received'
}, inplace=True)

# Shuffle data
df = df.sample(frac=1).reset_index(drop=True)

# Features and labels
X = df[['bytes_sent', 'bytes_received']]
y = df['label']

# Split data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("\nTraining AI model...")

# 🔥 Balanced model (VERY IMPORTANT FIX)
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight='balanced'
)

model.fit(X_train, y_train)

# Test the model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\nModel trained successfully!")
print(f"Accuracy: {accuracy * 100:.2f}%")
print("\nDetailed Report:")
print(classification_report(y_test, y_pred))

# Save the model
os.makedirs('model', exist_ok=True)
with open('model/intrusion_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Model saved to model/intrusion_model.pkl")

# 🔥 DEBUG CHECK (IMPORTANT)
print("Model expects features:", model.n_features_in_)