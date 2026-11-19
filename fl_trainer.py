"""
fl_trainer.py
=============
Layer 2 of the full pipeline.

Federated training across the per-slice datasets (one client per slice) with
Flower + FedAvg. The AGGREGATED global model is saved to
models/federated_model.pt together with a decision threshold calibrated on
the pooled validation data (best F1).

If Flower's simulation backend (Ray) is not available on this machine, the
same clients are run in-process with an equivalent FedAvg loop.
"""

import os
from collections import OrderedDict
from typing import Dict, List, Tuple

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.metrics import classification_report, f1_score, precision_recall_curve
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, TensorDataset

from features import INPUT_DIM
from model import MODEL_PATH, SliceSecurityNet, save_model

CFG = {
    "data_dir":         "data",
    "model_path":       MODEL_PATH,
    "learning_rate":    1e-3,
    "local_epochs":     3,
    "batch_size":       64,
    "test_split":       0.2,
    "num_rounds":       10,
    "dp_epsilon":       None,       # e.g. 1.0 to enable DP-SGD (pip install opacus)
    "dp_max_grad_norm": 1.0,
    "random_seed":      42,
    "engine":           os.getenv("FL_ENGINE", "auto"),   # auto | flower | local
}

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
torch.manual_seed(CFG["random_seed"])


# ─────────────────────────────────────────────────────────────
# DATA / TRAINING HELPERS
# ─────────────────────────────────────────────────────────────

def load_slice_data(csv_path: str) -> Tuple[DataLoader, DataLoader]:
    df = pd.read_csv(csv_path)
    y = df["label"].values.astype(int)
    X = df.drop(columns=["label"]).values.astype(np.float32)
    if X.shape[1] != INPUT_DIM:
        raise ValueError(f"{csv_path} has {X.shape[1]} features, expected {INPUT_DIM}. "
                         "Re-run data_pipeline.py.")
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=CFG["test_split"], stratify=y,
                                              random_state=CFG["random_seed"])

    def loader(Xd, yd, shuffle):
        ds = TensorDataset(torch.tensor(Xd), torch.tensor(yd, dtype=torch.long))
        return DataLoader(ds, batch_size=CFG["batch_size"], shuffle=shuffle)

    return loader(X_tr, y_tr, True), loader(X_te, y_te, False)


def train(model: nn.Module, loader: DataLoader, epochs: int) -> float:
    model.to(DEVICE).train()
    optimizer = torch.optim.Adam(model.parameters(), lr=CFG["learning_rate"])
    if CFG["dp_epsilon"]:
        try:
            from opacus import PrivacyEngine
            model, optimizer, loader = PrivacyEngine().make_private_with_epsilon(
                module=model, optimizer=optimizer, data_loader=loader, epochs=epochs,
                target_epsilon=CFG["dp_epsilon"], target_delta=1e-5,
                max_grad_norm=CFG["dp_max_grad_norm"])
        except ImportError:
            print("  [warn] opacus not installed — DP-SGD disabled")
    criterion = nn.CrossEntropyLoss()
    total, n = 0.0, 0
    for _ in range(epochs):
        for Xb, yb in loader:
            Xb, yb = Xb.to(DEVICE), yb.to(DEVICE)
            optimizer.zero_grad()
            loss = criterion(model(Xb), yb)
            loss.backward()
            optimizer.step()
            total, n = total + loss.item(), n + 1
    return total / max(n, 1)


@torch.no_grad()
def predict_proba(model: nn.Module, loader: DataLoader) -> Tuple[np.ndarray, np.ndarray]:
    model.to(DEVICE).eval()
    probs, labels = [], []
    for Xb, yb in loader:
        probs.append(torch.softmax(model(Xb.to(DEVICE)), 1)[:, 1].cpu().numpy())
        labels.append(yb.numpy())
    return np.concatenate(probs), np.concatenate(labels)


def evaluate(model: nn.Module, loader: DataLoader, threshold: float = 0.5) -> Tuple[float, float, dict]:
    probs, labels = predict_proba(model, loader)
    preds = (probs >= threshold).astype(int)
    eps = 1e-7
    loss = float(-np.mean(labels * np.log(probs + eps) + (1 - labels) * np.log(1 - probs + eps)))
    f1 = f1_score(labels, preds, zero_division=0)
    report = classification_report(labels, preds, labels=[0, 1], target_names=["normal", "attack"],
                                   zero_division=0, output_dict=True)
    return loss, f1, report


def get_weights(model: nn.Module) -> List[np.ndarray]:
    return [v.cpu().numpy() for v in model.state_dict().values()]


def set_weights(model: nn.Module, weights: List[np.ndarray]):
    keys = model.state_dict().keys()
    model.load_state_dict(OrderedDict((k, torch.tensor(v)) for k, v in zip(keys, weights)), strict=True)


def calibrate_threshold(model: nn.Module, loaders: List[DataLoader]) -> float:
    """Pick the threshold with the best F1 on the pooled validation sets."""
    probs, labels = zip(*(predict_proba(model, l) for l in loaders))
    probs, labels = np.concatenate(probs), np.concatenate(labels)
    prec, rec, thr = precision_recall_curve(labels, probs)
    f1 = 2 * prec * rec / np.clip(prec + rec, 1e-9, None)
    best = int(np.argmax(f1[:-1])) if len(thr) else 0
    return float(np.clip(thr[best], 0.05, 0.95)) if len(thr) else 0.5


# ─────────────────────────────────────────────────────────────
# CLIENT
# ─────────────────────────────────────────────────────────────

class SliceTrainer:
    """Plain client logic, shared by the Flower client and the local engine."""

    def __init__(self, client_id: int, csv_path: str):
        self.cid = client_id
        self.train_loader, self.test_loader = load_slice_data(csv_path)
        self.model = SliceSecurityNet()

    def fit(self, parameters):
        set_weights(self.model, parameters)
        loss = train(self.model, self.train_loader, CFG["local_epochs"])
        return get_weights(self.model), len(self.train_loader.dataset), {"loss": float(loss)}

    def evaluate(self, parameters):
        set_weights(self.model, parameters)
        loss, f1, rep = evaluate(self.model, self.test_loader)
        return loss, len(self.test_loader.dataset), {
            "f1": float(f1), "precision": float(rep["attack"]["precision"]),
            "recall": float(rep["attack"]["recall"])}


def weighted_average(metrics: List[Tuple[int, Dict]]) -> Dict:
    total = sum(n for n, _ in metrics)
    return {k: sum(n * m[k] for n, m in metrics) / total for k in ("f1", "precision", "recall")}


def fedavg(results: List[Tuple[List[np.ndarray], int]]) -> List[np.ndarray]:
    total = sum(n for _, n in results)
    return [sum(w[i] * n for w, n in results) / total for i in range(len(results[0][0]))]


# ─────────────────────────────────────────────────────────────
# ENGINES
# ─────────────────────────────────────────────────────────────

def run_local(trainers: List[SliceTrainer], init: List[np.ndarray]) -> List[np.ndarray]:
    weights = init
    for rnd in range(1, CFG["num_rounds"] + 1):
        results = [t.fit(weights) for t in trainers]
        weights = fedavg([(w, n) for w, n, _ in results])
        evals = [t.evaluate(weights) for t in trainers]
        m = weighted_average([(n, met) for _, n, met in evals])
        print(f"  Round {rnd:>2}  F1={m['f1']:.4f}  precision={m['precision']:.4f}  recall={m['recall']:.4f}")
    return weights


def run_flower(csv_files: List[str], init: List[np.ndarray]) -> List[np.ndarray]:
    import flwr as fl

    class SliceClient(fl.client.NumPyClient):
        def __init__(self, cid, path):
            self.t = SliceTrainer(cid, path)

        def get_parameters(self, config):
            return get_weights(self.t.model)

        def fit(self, parameters, config):
            return self.t.fit(parameters)

        def evaluate(self, parameters, config):
            return self.t.evaluate(parameters)

    class SavingFedAvg(fl.server.strategy.FedAvg):
        """FedAvg that keeps the latest aggregated parameters."""
        latest = None

        def aggregate_fit(self, server_round, results, failures):
            params, metrics = super().aggregate_fit(server_round, results, failures)
            if params is not None:
                SavingFedAvg.latest = fl.common.parameters_to_ndarrays(params)
            return params, metrics

    n = len(csv_files)
    strategy = SavingFedAvg(
        fraction_fit=1.0, fraction_evaluate=1.0,
        min_fit_clients=n, min_evaluate_clients=n, min_available_clients=n,
        evaluate_metrics_aggregation_fn=weighted_average,
        initial_parameters=fl.common.ndarrays_to_parameters(init),
    )
    history = fl.simulation.start_simulation(
        client_fn=lambda cid: SliceClient(int(cid), csv_files[int(cid)]).to_client(),
        num_clients=n,
        config=fl.server.ServerConfig(num_rounds=CFG["num_rounds"]),
        strategy=strategy,
        client_resources={"num_cpus": 1},
    )
    for rnd, f1 in history.metrics_distributed.get("f1", []):
        print(f"  Round {rnd:>2}  F1={f1:.4f}")
    if SavingFedAvg.latest is None:
        raise RuntimeError("Flower returned no aggregated parameters")
    return SavingFedAvg.latest


def run() -> str:
    data_dir = CFG["data_dir"]
    csv_files = sorted(os.path.join(data_dir, f) for f in os.listdir(data_dir)
                       if f.startswith("slice_") and f.endswith(".csv")) if os.path.isdir(data_dir) else []
    if not csv_files:
        raise FileNotFoundError("No slice CSVs found in data/. Run data_pipeline.py first.")

    engine = CFG["engine"]
    if engine == "auto":
        try:
            import flwr  # noqa: F401
            import ray   # noqa: F401
            engine = "flower"
        except ImportError:
            engine = "local"

    print(f"\n{'=' * 60}")
    print(f"  FL TRAINER — {len(csv_files)} clients | {CFG['num_rounds']} rounds | engine={engine}")
    print(f"  DP-SGD: {'enabled (eps=' + str(CFG['dp_epsilon']) + ')' if CFG['dp_epsilon'] else 'disabled'}")
    print(f"  Device: {DEVICE}")
    print(f"{'=' * 60}")

    init = get_weights(SliceSecurityNet())
    if engine == "flower":
        weights = run_flower(csv_files, init)
    else:
        trainers = [SliceTrainer(i, p) for i, p in enumerate(csv_files)]
        weights = run_local(trainers, init)

    # ── Final evaluation of the AGGREGATED model ─────────────
    global_model = SliceSecurityNet()
    set_weights(global_model, weights)
    test_loaders = [load_slice_data(p)[1] for p in csv_files]
    threshold = calibrate_threshold(global_model, test_loaders)

    print(f"\n{'=' * 60}\n  GLOBAL MODEL (threshold={threshold:.3f})\n{'=' * 60}")
    per_slice = {}
    for i, loader in enumerate(test_loaders):
        _, f1, rep = evaluate(global_model, loader, threshold)
        per_slice[i] = {"f1": round(f1, 4), "precision": round(rep["attack"]["precision"], 4),
                        "recall": round(rep["attack"]["recall"], 4)}
        print(f"  Slice {i}: F1={f1:.4f}  precision={rep['attack']['precision']:.4f}  "
              f"recall={rep['attack']['recall']:.4f}")
    print("  Note: validation uses the same data sources as training; see IMPROVEMENTS.md 1.3.")

    save_model(global_model, CFG["model_path"], threshold=threshold, per_slice_metrics=per_slice,
               rounds=CFG["num_rounds"], engine=engine)
    print(f"\n  Model saved -> {CFG['model_path']}")
    return CFG["model_path"]


if __name__ == "__main__":
    run()
