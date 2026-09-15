"""Deterministic lightweight ML path: Random Forest classification + Isolation Forest."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from random import Random
from time import perf_counter

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from app.flow.features import numeric_vector
from app.flow.schemas import FlowFeatures, TrafficLabel


MODEL_VERSION = "rf-iforest-synthetic-v1"
_LABELS = [label.value for label in TrafficLabel]


def _sample(rng: Random, label: TrafficLabel) -> list[float]:
    """Generate labelled feature vectors for reproducible offline model training."""
    if label is TrafficLabel.NORMAL:
        return [rng.uniform(25, 150), rng.uniform(12_000, 120_000), rng.uniform(.4, 2.5), 1, rng.randint(1, 3), rng.randint(1, 3), rng.uniform(.02, .2), rng.uniform(0, .45), rng.choice([0, 0, 15]), rng.uniform(2.0, 3.3), rng.randint(1, 8), rng.uniform(.15, .55), rng.uniform(.2, .55), rng.uniform(0, .12), rng.uniform(.8, 1), rng.uniform(0, .18)]
    if label is TrafficLabel.DDOS:
        return [rng.uniform(8_000, 45_000), rng.uniform(500_000, 4_000_000), rng.uniform(.03, .3), rng.randint(12, 160), 1, rng.randint(1, 2), rng.uniform(.0001, .004), rng.uniform(0, .2), 0, 0, 0, 0, rng.uniform(.7, 1), rng.uniform(.65, 1), rng.uniform(0, .25), rng.uniform(.65, 1)]
    if label is TrafficLabel.C2_BEACONING:
        return [rng.uniform(8, 55), rng.uniform(1_500, 18_000), rng.uniform(.2, 1), 1, 1, 1, rng.uniform(.03, .09), rng.uniform(.88, 1), 0, 0, 0, 0, rng.uniform(.65, 1), rng.uniform(0, .1), rng.uniform(.8, 1), rng.uniform(.35, .85)]
    if label in {TrafficLabel.DNS_TUNNELING, TrafficLabel.DGA}:
        return [rng.uniform(20, 350), rng.uniform(4_000, 80_000), rng.uniform(.03, .4), 1, 1, 1, rng.uniform(.002, .04), rng.uniform(0, .5), rng.randint(35, 110), rng.uniform(3.7, 5.0), 1, rng.uniform(.75, 1), rng.uniform(.5, 1), 0, rng.uniform(.6, 1), rng.uniform(.45, .95)]
    return [rng.uniform(5, 160), rng.uniform(300, 20_000), rng.uniform(.01, .2), 1, rng.randint(5, 40), rng.randint(8, 80), rng.uniform(.001, .02), rng.uniform(0, .2), 0, 0, 0, 0, rng.uniform(.2, .8), rng.uniform(.65, 1), rng.uniform(0, .25), rng.uniform(.45, .95)]


def training_dataset(seed: int = 26145, samples_per_class: int = 160) -> tuple[np.ndarray, np.ndarray]:
    rng = Random(seed)
    rows: list[list[float]] = []
    labels: list[str] = []
    for label in TrafficLabel:
        for _ in range(samples_per_class):
            rows.append(_sample(rng, label))
            labels.append(label.value)
    return np.asarray(rows, dtype=float), np.asarray(labels)


@dataclass(frozen=True)
class ModelMetrics:
    precision: float
    recall: float
    f1: float
    labels: list[str]
    confusion_matrix: list[list[int]]


@dataclass
class ModelBundle:
    classifier: Pipeline
    anomaly_detector: Pipeline
    metrics: ModelMetrics

    def infer(self, features: FlowFeatures) -> tuple[TrafficLabel, float, float, float]:
        started = perf_counter()
        vector = np.asarray([numeric_vector(features)], dtype=float)
        probabilities = self.classifier.predict_proba(vector)[0]
        classes = self.classifier.classes_
        index = int(np.argmax(probabilities))
        predicted = TrafficLabel(str(classes[index]))
        # Isolation Forest is fitted exclusively on the normal subset.  Its
        # decision function is positive for normal observations.
        normality = float(self.anomaly_detector.decision_function(vector)[0])
        anomaly = max(0.0, min(1.0, 0.5 - normality * 3.2))
        elapsed_ms = round((perf_counter() - started) * 1_000, 4)
        return predicted, float(probabilities[index]), anomaly, elapsed_ms


@lru_cache(maxsize=1)
def load_models() -> ModelBundle:
    """Train once at service start; the same fixed data produces the same model."""
    features, labels = training_dataset()
    train_x, test_x, train_y, test_y = train_test_split(features, labels, test_size=.25, random_state=26145, stratify=labels)
    classifier = Pipeline([
        ("scale", StandardScaler()),
        ("forest", RandomForestClassifier(n_estimators=180, max_depth=12, min_samples_leaf=2, random_state=26145, n_jobs=1)),
    ])
    classifier.fit(train_x, train_y)
    predicted = classifier.predict(test_x)
    precision, recall, f1, _ = precision_recall_fscore_support(test_y, predicted, labels=_LABELS, average="weighted", zero_division=0)
    metrics = ModelMetrics(
        precision=round(float(precision), 4), recall=round(float(recall), 4), f1=round(float(f1), 4),
        labels=_LABELS, confusion_matrix=confusion_matrix(test_y, predicted, labels=_LABELS).tolist(),
    )
    normal_x = features[labels == TrafficLabel.NORMAL.value]
    anomaly_detector = Pipeline([
        ("scale", StandardScaler()),
        ("isolation_forest", IsolationForest(n_estimators=160, contamination=.08, random_state=26145)),
    ])
    anomaly_detector.fit(normal_x)
    return ModelBundle(classifier=classifier, anomaly_detector=anomaly_detector, metrics=metrics)
