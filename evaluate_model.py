# evaluate_model.py

import pandas as pd
import pickle
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay

print("Loading model and dataset...")

df = pd.read_csv('phishing_dataset.csv')
X  = df.drop(['index', 'Result'], axis=1)
y  = df['Result']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

with open('phishing_model.pkl', 'rb') as f:
    model = pickle.load(f)

y_pred = model.predict(X_test)

# Confusion Matrix
cm   = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(
    confusion_matrix=cm,
    display_labels=['Legitimate', 'Phishing']
)
disp.plot(cmap='Blues')
plt.title('Confusion Matrix')
plt.tight_layout()
plt.savefig('static/confusion_matrix.png')
print("Saved: static/confusion_matrix.png")

# Feature Importance
importances   = model.feature_importances_
feature_names = list(X.columns)

plt.figure(figsize=(12, 6))
plt.barh(feature_names, importances, color='steelblue')
plt.xlabel('Importance Score')
plt.title('Feature Importance')
plt.tight_layout()
plt.savefig('static/feature_importance.png')
print("Saved: static/feature_importance.png")

plt.show()
print("Evaluation complete!")