"""
CyberSentinel - Dataset Loader
Loads and preprocesses the UCI Phishing Websites Dataset (UCI ID: 327).
Provides reproducible train-test splits for both the 30-feature benchmark
and the URL-extractable real-time feature subset.
"""

import os
from typing import Tuple, List, Dict, Any
import pandas as pd
from sklearn.model_selection import train_test_split

# URL-extractable feature subset from the UCI dataset
URL_FEATURE_COLUMNS = [
    "having_ip_address",
    "url_length",
    "shortining_service",
    "having_at_symbol",
    "double_slash_redirecting",
    "prefix_suffix",
    "having_sub_domain",
    "port",
    "https_token",
    "abnormal_url",
]

DATA_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "phishing_dataset.csv")


def load_dataset(use_cache: bool = True) -> Tuple[pd.DataFrame, pd.Series, List[str]]:
    """
    Load the UCI Phishing Websites dataset.
    Prioritizes local cached CSV file, falls back to ucimlrepo if unavailable.

    Returns:
        X (pd.DataFrame): 30 features
        y (pd.Series): Target labels (1 = Legitimate, -1 = Phishing)
        feature_names (List[str]): List of all 30 feature names
    """
    if use_cache and os.path.exists(DATA_PATH) and os.path.getsize(DATA_PATH) > 1000:
        df = pd.read_csv(DATA_PATH)
        X = df.drop(columns=["result"])
        y = df["result"]
        return X, y, list(X.columns)

    # Fallback to ucimlrepo
    try:
        from ucimlrepo import fetch_ucirepo
        dataset = fetch_ucirepo(id=327)
        X = dataset.data.features
        y = dataset.data.targets["result"]

        # Cache locally for offline execution
        os.makedirs(os.path.dirname(DATA_PATH), exist_ok=True)
        df_combined = pd.concat([X, y], axis=1)
        df_combined.to_csv(DATA_PATH, index=False)

        return X, y, list(X.columns)
    except Exception as exc:
        raise RuntimeError(f"Failed to load dataset: {exc}") from exc


def get_train_test_data(
    test_size: float = 0.2,
    random_state: int = 42,
    url_only: bool = False
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """
    Splits the dataset into stratified training and testing sets.

    Args:
        test_size: Proportion of test samples (default 0.2 -> 2,211 test samples)
        random_state: Seed for reproducibility (default 42)
        url_only: If True, returns only the 10 URL-extractable features.

    Returns:
        X_train, X_test, y_train, y_test
    """
    X, y, _ = load_dataset()

    if url_only:
        X = X[URL_FEATURE_COLUMNS]

    return train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y
    )


if __name__ == "__main__":
    X, y, features = load_dataset()
    print(f"Loaded dataset: {X.shape[0]} samples, {X.shape[1]} features.")
    print(f"Target distribution:\n{y.value_counts()}")
    print(f"URL-only feature subset ({len(URL_FEATURE_COLUMNS)} features): {URL_FEATURE_COLUMNS}")