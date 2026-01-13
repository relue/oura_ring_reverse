"""
ML Model Inference Framework for Oura Ring Data

Loads and runs decrypted PyTorch TorchScript models for health analytics.
All models use REAL neural network weights - NO heuristics.

Key Models (all Pure PyTorch, no custom ops needed):
- SleepNet: Sleep stage classification (Awake/Light/Deep/REM)
- WHR: Waking Heart Rate calculation
- Activity Detection: Automatic workout detection
- CVA: Cardiovascular Age estimation
- Energy Expenditure: Calorie calculation
- Step Counter: Step counting from motion data
- Illness Detection: Early illness detection

Usage:
    from ml_inference import SleepNetModel

    # Sleep staging with real neural network
    sleep_model = SleepNetModel()
    result = sleep_model.predict_from_reader(reader)
    print(f"Deep sleep: {result.deep_seconds // 60} min")
    print(f"REM sleep: {result.rem_seconds // 60} min")
"""

# Register custom ops first (needed for some orchestration models)
from . import custom_ops
custom_ops.register_oura_ops()

# Import model loader
from .model_loader import ModelLoader, ModelInfo, get_available_models

# Import neural network model wrappers
from .sleepnet import SleepNetModel, SleepNetResult

# Model registry - maps purpose to actual neural network model
MODEL_REGISTRY = {
    # Sleep Analysis
    "sleep_staging": "sleepnet_1_0_0.pt",  # 4.4MB neural network
    "sleep_bdi": "sleepnet_bdi_0_2_2.pt",  # Breathing Disturbance Index

    # Heart Rate Analysis
    "waking_heart_rate": "whr_3_1_2.pt",  # 4.0MB neural network
    "hr_analysis": "halite_1_1_0.pt",  # 3.8MB neural network
    "awhr_imputation": "awhr_imputation_1_1_0.pt",  # 869KB

    # Activity Analysis
    "activity_detection": "automatic_activity_detection_3_0_8.pt",  # 5.4MB
    "step_counter": "step_counter_1_2_0.pt",  # 125KB
    "energy_expenditure": "energy_expenditure_0_0_10.pt",  # 1.4MB

    # Health Analysis
    "cardiovascular_age": "cva_2_0_3.pt",  # 7.2MB neural network
    "illness_detection": "illness_detection_0_4_1.pt",  # 690KB

    # Other
    "popsicle": "popsicle_1_5_4.pt",  # Unknown purpose
}

__all__ = [
    # Model loader
    "ModelLoader",
    "ModelInfo",
    "get_available_models",

    # Neural network wrappers
    "SleepNetModel",
    "SleepNetResult",

    # Registry
    "MODEL_REGISTRY",
]
