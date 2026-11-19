"""
model.py
========
SliceSecurityNet definition plus save/load helpers, shared by the FL trainer
and the detection engine (so detection does not need Flower installed).
"""

import os
from typing import List

import torch
import torch.nn as nn

from features import INPUT_DIM

MODEL_PATH = os.getenv("SLICESHIELD_MODEL", "models/federated_model.pt")
HIDDEN_DIMS = [128, 64, 32]
DROPOUT = 0.3


class SliceSecurityNet(nn.Module):
    """MLP binary classifier (0 = normal, 1 = attack).

    Uses LayerNorm rather than BatchNorm: it works with batch size 1 at
    inference time and is compatible with Opacus DP-SGD.
    """

    def __init__(self, input_dim: int = INPUT_DIM, hidden_dims: List[int] = HIDDEN_DIMS,
                 num_classes: int = 2, dropout: float = DROPOUT):
        super().__init__()
        layers, in_d = [], input_dim
        for h in hidden_dims:
            layers += [nn.Linear(in_d, h), nn.LayerNorm(h), nn.ReLU(), nn.Dropout(dropout)]
            in_d = h
        layers.append(nn.Linear(in_d, num_classes))
        self.net = nn.Sequential(*layers)

    def forward(self, x):
        return self.net(x)


def save_model(model: nn.Module, path: str = MODEL_PATH, **meta) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    torch.save({"state_dict": model.state_dict(), "input_dim": INPUT_DIM,
                "hidden_dims": HIDDEN_DIMS, **meta}, path)
    return path


def load_model(path: str = MODEL_PATH) -> SliceSecurityNet:
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found — run `python run_pipeline.py --train-only` first")
    ckpt = torch.load(path, map_location="cpu", weights_only=False)
    if not isinstance(ckpt, dict) or "state_dict" not in ckpt:
        raise ValueError(f"{path} is an old-format checkpoint (untrained); retrain with the current pipeline")
    model = SliceSecurityNet(ckpt["input_dim"], ckpt["hidden_dims"])
    model.load_state_dict(ckpt["state_dict"])
    model.eval()
    model.threshold = float(ckpt.get("threshold", 0.5))
    return model
