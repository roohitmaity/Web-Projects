# step:1
import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import joblib
import os
import warnings

warnings.filterwarnings('ignore')

print("=" * 20)
print("DETECTING ANOMALIES")
print("=" * 20)


# 1. LOAD DATA

use_sample = True

if use_sample:
    # Load first 500,000 rows for faster testing
    df = pd.read_csv('data/rba-dataset.csv', nrows=10000)
    print(f"Using SAMPLE of {len(df)} rows :")
else:
    df = pd.read_csv('data/rba-dataset.csv')
    print(f"Loaded {len(df):,} login attempts")

print(f"Columns found: {list(df.columns)}")

# 2. FEATURE ENGINEERING
print("\n[1] Engineering features...")

# Extract hour from Login Timestamp
print("  • Extracting time features...")
df['Login Timestamp'] = pd.to_datetime(df['Login Timestamp'])
df['login_hour'] = df['Login Timestamp'].dt.hour
df['login_weekday'] = df['Login Timestamp'].dt.weekday
df['login_day'] = df['Login Timestamp'].dt.day

# Convert IP Address to features
print("  • Processing IP addresses...")


def ip_to_features(ip):
    """Convert IP to 4 octet features"""
    try:
        parts = [int(x) for x in str(ip).split('.')]
        # Normalize to 0-1 range
        return [p / 255.0 for p in parts[:4]]  # Take first 4 parts
    except:
        return [0, 0, 0, 0]


# Apply IP conversion
ip_features = df['IP Address'].apply(ip_to_features)
df['ip_1'] = [f[0] for f in ip_features]
df['ip_2'] = [f[1] for f in ip_features]
df['ip_3'] = [f[2] for f in ip_features]
df['ip_4'] = [f[3] for f in ip_features]

# Encode categorical variables
print("  • Encoding categorical variables...")
le_country = LabelEncoder()
le_region = LabelEncoder()
le_city = LabelEncoder()
le_device = LabelEncoder()
le_browser = LabelEncoder()
le_os = LabelEncoder()

# Handle potential NaN values
df['Country'] = df['Country'].fillna('Unknown')
df['Region'] = df['Region'].fillna('Unknown')
df['City'] = df['City'].fillna('Unknown')
df['Device Type'] = df['Device Type'].fillna('Unknown')
df['Browser Name and Version'] = df['Browser Name and Version'].fillna('Unknown')
df['OS Name and Version'] = df['OS Name and Version'].fillna('Unknown')

df['country_code'] = le_country.fit_transform(df['Country'])
df['region_code'] = le_region.fit_transform(df['Region'])
df['city_code'] = le_city.fit_transform(df['City'])
df['device_code'] = le_device.fit_transform(df['Device Type'])
df['browser_code'] = le_browser.fit_transform(df['Browser Name and Version'])
df['os_code'] = le_os.fit_transform(df['OS Name and Version'])

# Process numerical features
print("  • Processing numerical features...")
# Normalize Round-Trip Time (handle infinite/NaN values)
df['Round-Trip Time [ms]'] = df['Round-Trip Time [ms]'].fillna(df['Round-Trip Time [ms]'].median())
# Log transform to handle wide range
df['rtt_log'] = np.log1p(df['Round-Trip Time [ms]'])

# Process ASN
df['ASN'] = df['ASN'].fillna(0)
# Normalize ASN (divide by max to get 0-1 range)
max_asn = df['ASN'].max()
df['asn_norm'] = df['ASN'] / max_asn if max_asn > 0 else 0

# Login Success (convert boolean to int)
df['login_success'] = df['Login Successful'].astype(int)

# Attack labels (for evaluation)
df['is_attack_ip'] = df['Is Attack IP'].astype(int)
df['is_account_takeover'] = df['Is Account Takeover'].astype(int)
# Combined attack label (1 if either is true)
df['is_attack'] = (df['is_attack_ip'] | df['is_account_takeover']).astype(int)

print(f"  • Attack rate: {df['is_attack'].mean() * 100:.2f}%")

# Select features for model
feature_cols = [
    'login_hour', 'login_weekday', 'login_day',
    'country_code', 'region_code', 'city_code',
    'device_code', 'browser_code', 'os_code',
    'ip_1', 'ip_2', 'ip_3', 'ip_4',
    'rtt_log', 'asn_norm', 'login_success'
]

print(f"\n[2] Feature matrix: {len(feature_cols)} features")
print(f"Features: {feature_cols}")

X = df[feature_cols].values
print(f"Feature matrix shape: {X.shape}")

# 3. NORMALIZE DATA
print("\n[3] Normalizing features...")
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X)

# Save preprocessing objects
os.makedirs('models', exist_ok=True)
joblib.dump(scaler, 'models/scaler.pkl')
joblib.dump(le_country, 'models/label_encoder_country.pkl')
joblib.dump(le_region, 'models/label_encoder_region.pkl')
joblib.dump(le_city, 'models/label_encoder_city.pkl')
joblib.dump(le_device, 'models/label_encoder_device.pkl')
joblib.dump(le_browser, 'models/label_encoder_browser.pkl')
joblib.dump(le_os, 'models/label_encoder_os.pkl')
joblib.dump(feature_cols, 'models/feature_columns.pkl')
print("✓ Saved scaler and encoders")

# 4. BUILD AUTOENCODER
print("\n[4] Building AutoEncoder model...")

input_dim = X_scaled.shape[1]
print(f"Input dimension: {input_dim}")

# AutoEncoder architecture
encoder_input = layers.Input(shape=(input_dim,))
x = layers.Dense(32, activation='relu')(encoder_input)
x = layers.Dropout(0.1)(x)
x = layers.Dense(16, activation='relu')(x)
x = layers.Dropout(0.1)(x)
encoded = layers.Dense(8, activation='relu')(x)  # Bottleneck

x = layers.Dense(16, activation='relu')(encoded)
x = layers.Dropout(0.1)(x)
x = layers.Dense(32, activation='relu')(x)
x = layers.Dropout(0.1)(x)
decoded = layers.Dense(input_dim, activation='sigmoid')(x)

autoencoder = keras.Model(encoder_input, decoded)
autoencoder.compile(optimizer='adam', loss='mse')

print(autoencoder.summary())

# 5. TRAIN AUTOENCODER
print("\n[5] Training AutoEncoder...")

# Use normal data for training (unsupervised approach)
# In real life, we assume most data is normal
normal_mask = df['is_attack'] == 0
normal_data = X_scaled[normal_mask]

print(f"Training on {len(normal_data):,} normal samples")
print(f"Anomalies held out for testing: {(~normal_mask).sum():,}")

# Early stopping callback
early_stop = keras.callbacks.EarlyStopping(
    monitor='val_loss',
    patience=3,
    restore_best_weights=True
)

# Train
history = autoencoder.fit(
    normal_data, normal_data,
    epochs=20,
    batch_size=2048,  # Larger batch for speed
    validation_split=0.1,
    callbacks=[early_stop],
    verbose=1
)

# Save model
autoencoder.save('models/autoencoder.keras')
print("✓ Saved AutoEncoder model")

# 6. ISOLATION FOREST
print("\n[6] Training Isolation Forest...")

# Use sample for Isolation Forest (it's faster)
iso_sample_size = min(10000, len(normal_data))
iso_sample_idx = np.random.choice(len(normal_data), iso_sample_size, replace=False)
iso_sample = normal_data[iso_sample_idx]

iso_forest = IsolationForest(
    n_estimators=100,
    contamination=0.02,
    random_state=42,
    n_jobs=-1
)

iso_forest.fit(iso_sample)
joblib.dump(iso_forest, 'models/isolation_forest.pkl')
print("✓ Saved Isolation Forest model")

# 7. DETECT ANOMALIES
print("\n[7] Detecting anomalies on full dataset...")

# Process in batches to avoid memory issues
batch_size = 50000
n_samples = len(X_scaled)
n_batches = (n_samples + batch_size - 1) // batch_size

all_mse = []
all_iso_pred = []

print(f"Processing {n_batches} batches of {batch_size} samples...")

for i in range(n_batches):
    start_idx = i * batch_size
    end_idx = min((i + 1) * batch_size, n_samples)

    batch = X_scaled[start_idx:end_idx]

    # AutoEncoder predictions
    reconstructed = autoencoder.predict(batch, verbose=0)
    mse = np.mean(np.square(batch - reconstructed), axis=1)
    all_mse.extend(mse)

    # Isolation Forest predictions
    iso_pred = iso_forest.predict(batch)
    all_iso_pred.extend(iso_pred)

    if (i + 1) % 5 == 0:
        print(f"  Processed {end_idx:,}/{n_samples:,} samples ({(end_idx / n_samples) * 100:.1f}%)")

# Convert to numpy arrays
all_mse = np.array(all_mse)
all_iso_pred = np.array(all_iso_pred)

# Set threshold at 95th percentile
ae_threshold = np.percentile(all_mse, 95)
ae_anomalies = all_mse > ae_threshold
iso_anomalies = all_iso_pred == -1

# Add to dataframe
df['ae_score'] = all_mse
df['ae_anomaly'] = ae_anomalies
df['iso_anomaly'] = iso_anomalies
df['true_attack'] = df['is_attack']

# 8. EVALUATE
print("\n[8] Results:")
print("-" * 50)

# AutoEncoder performance
ae_correct = (df['ae_anomaly'] == df['true_attack']).sum()
ae_accuracy = ae_correct / len(df) * 100

# Calculate precision/recall for AutoEncoder
ae_true_pos = ((df['ae_anomaly'] == True) & (df['true_attack'] == True)).sum()
ae_false_pos = ((df['ae_anomaly'] == True) & (df['true_attack'] == False)).sum()
ae_false_neg = ((df['ae_anomaly'] == False) & (df['true_attack'] == True)).sum()

ae_precision = ae_true_pos / (ae_true_pos + ae_false_pos) if (ae_true_pos + ae_false_pos) > 0 else 0
ae_recall = ae_true_pos / (ae_true_pos + ae_false_neg) if (ae_true_pos + ae_false_neg) > 0 else 0
ae_f1 = 2 * (ae_precision * ae_recall) / (ae_precision + ae_recall) if (ae_precision + ae_recall) > 0 else 0

print(f"AutoEncoder Results:")
print(f"  Accuracy:  {ae_accuracy:.2f}%")
print(f"  Precision: {ae_precision:.3f}")
print(f"  Recall:    {ae_recall:.3f}")
print(f"  F1-Score:  {ae_f1:.3f}")

# Isolation Forest performance
iso_correct = (df['iso_anomaly'] == df['true_attack']).sum()
iso_accuracy = iso_correct / len(df) * 100

iso_true_pos = ((df['iso_anomaly'] == True) & (df['true_attack'] == True)).sum()
iso_false_pos = ((df['iso_anomaly'] == True) & (df['true_attack'] == False)).sum()
iso_false_neg = ((df['iso_anomaly'] == False) & (df['true_attack'] == True)).sum()

iso_precision = iso_true_pos / (iso_true_pos + iso_false_pos) if (iso_true_pos + iso_false_pos) > 0 else 0
iso_recall = iso_true_pos / (iso_true_pos + iso_false_neg) if (iso_true_pos + iso_false_neg) > 0 else 0
iso_f1 = 2 * (iso_precision * iso_recall) / (iso_precision + iso_recall) if (iso_precision + iso_recall) > 0 else 0

print(f"\nIsolation Forest Results:")
print(f"  Accuracy:  {iso_accuracy:.2f}%")
print(f"  Precision: {iso_precision:.3f}")
print(f"  Recall:    {iso_recall:.3f}")
print(f"  F1-Score:  {iso_f1:.3f}")

# 9. SAVE RESULTS
print("\n[9] Saving results...")

# Save only necessary columns to keep file size manageable
save_cols = [
    'Login Timestamp', 'User ID', 'IP Address', 'Country',
    'Device Type', 'Login Successful', 'Is Attack IP', 'Is Account Takeover',
    'login_hour', 'login_weekday', 'ae_score', 'ae_anomaly', 'iso_anomaly',
    'true_attack'
]
df[save_cols].to_csv('data/detection_results.csv', index=False)
print(f"✓ Saved detection results to data/detection_results.csv")
print(f"  Found {ae_anomalies.sum():,} anomalies ({ae_anomalies.sum() / len(df) * 100:.2f}%)")
print(f"  Actual attacks: {df['true_attack'].sum():,}")

# Save summary statistics
summary = {
    'total_samples': len(df),
    'actual_attacks': int(df['true_attack'].sum()),
    'autoencoder_detected': int(ae_anomalies.sum()),
    'isolation_forest_detected': int(iso_anomalies.sum()),
    'autoencoder_accuracy': float(ae_accuracy),
    'autoencoder_precision': float(ae_precision),
    'autoencoder_recall': float(ae_recall),
    'autoencoder_f1': float(ae_f1),
    'isolation_forest_accuracy': float(iso_accuracy),
    'isolation_forest_precision': float(iso_precision),
    'isolation_forest_recall': float(iso_recall),
    'isolation_forest_f1': float(iso_f1),
    'features_used': feature_cols
}

import json

with open('models/summary_stats.json', 'w') as f:
    json.dump(summary, f, indent=2)

print("\n" + "=" * 20)
print("ANOMALY DETECTION COMPLETE!")
print("=" * 20)
