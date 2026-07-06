# train_model.py

import pandas as pd
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import re
from urllib.parse import urlparse

def extract_features(url):
    having_ip = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0  # Fix 1: re.match → re.search
    url_length = len(url)                                             # Fix 2: removed bad indent
    https = 1 if "https" in url else 0                               # Fix 3 & 4: proper ternary syntax
    return [having_ip, url_length, https]


print("=" * 50)
print("   PHISHING DETECTION MODEL TRAINING")
print("=" * 50)

print("\nLoading dataset...")
df = pd.read_csv('phishing_dataset.csv')

print(f"Dataset shape      : {df.shape}")
print(f"Label distribution :\n{df['Result'].value_counts()}")

X = df.drop(['index', 'Result'], axis=1)
y = df['Result']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print(f"\nTraining samples   : {len(X_train)}")
print(f"Testing  samples   : {len(X_test)}")

print("\nTraining Random Forest model...")
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=15,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42
)
model.fit(X_train, y_train)
print("Training complete!")

y_pred   = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred) * 100
print(f"\nModel Accuracy     : {accuracy:.2f}%")
print("\nDetailed Report:")
print(classification_report(
    y_test, y_pred,
    target_names=['Legitimate', 'Phishing']
))

model_path = 'phishing_model.pkl'
with open(model_path, 'wb') as f:
    pickle.dump(model, f)

if os.path.exists(model_path):
    size = os.path.getsize(model_path)
    print(f"\nModel saved!")
    print(f"File : {model_path}")
    print(f"Size : {size / 1024:.1f} KB")
    print("=" * 50)
else:
    print("Error: Model not saved.")
