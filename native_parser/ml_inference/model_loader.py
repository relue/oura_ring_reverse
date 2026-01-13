"""
TorchScript Model Loader for Oura Ring ML Models

Provides infrastructure for loading and running the 28 decrypted PyTorch models.

Usage:
    from ml_inference import ModelLoader

    loader = ModelLoader()

    # List available models
    for model in loader.list_models():
        print(f"{model.name}: {model.purpose}")

    # Load a model
    sleep_model = loader.load("sleepstaging_2_6_0")

    # Run inference
    output = sleep_model(input_tensor)
"""

import os
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple
from functools import lru_cache

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    torch = None

# Default models directory
DEFAULT_MODELS_DIR = Path(__file__).parent.parent / "decrypted_models"


@dataclass
class ModelInfo:
    """Information about a model."""
    name: str
    version: str
    filename: str
    size_bytes: int
    category: str
    purpose: str


# Model catalog with metadata
MODEL_CATALOG: Dict[str, Dict[str, str]] = {
    # Sleep models
    "sleepstaging_2_6_0": {
        "category": "sleep",
        "purpose": "Sleep stage classification (Awake/Light/Deep/REM)",
    },
    "sleepstaging_2_5_3": {
        "category": "sleep",
        "purpose": "Sleep stage classification (older version)",
    },
    "sleepnet_1_0_0": {
        "category": "sleep",
        "purpose": "Deep sleep analysis neural network",
    },
    "sleepnet_moonstone_1_1_0": {
        "category": "sleep",
        "purpose": "Sleep analysis for Ring 4 (Moonstone)",
    },
    "sleepnet_bdi_0_2_2": {
        "category": "sleep",
        "purpose": "Sleep quality/disturbance index",
    },
    "insomnia_0_1_4": {
        "category": "sleep",
        "purpose": "Insomnia detection",
    },

    # Heart rate models
    "whr_3_1_2": {
        "category": "heart_rate",
        "purpose": "Waking Heart Rate estimation",
    },
    "whr_2_6_0": {
        "category": "heart_rate",
        "purpose": "Waking Heart Rate (older version)",
    },
    "awhr_imputation_1_1_0": {
        "category": "heart_rate",
        "purpose": "Fill missing HR gaps",
    },
    "awhr_profile_selector_0_0_1": {
        "category": "heart_rate",
        "purpose": "HR processing profile selection",
    },
    "dhrv_imputation_1_0_3": {
        "category": "heart_rate",
        "purpose": "Fill missing HRV gaps",
    },
    "halite_1_1_0": {
        "category": "heart_rate",
        "purpose": "Advanced HR analysis",
    },

    # Cardiovascular models
    "cva_2_0_3": {
        "category": "cardiovascular",
        "purpose": "Cardiovascular Age estimation",
    },
    "cva_1_2_2": {
        "category": "cardiovascular",
        "purpose": "Cardiovascular Age (older version)",
    },
    "cva_calibrator_1_2_3": {
        "category": "cardiovascular",
        "purpose": "CVA calibration/personalization",
    },

    # Activity models
    "automatic_activity_detection_3_0_8": {
        "category": "activity",
        "purpose": "Detect workout type (walking/running/cycling/etc)",
    },
    "step_counter_1_2_0": {
        "category": "activity",
        "purpose": "Count steps from motion",
    },
    "steps_motion_decoder_1_0_0": {
        "category": "activity",
        "purpose": "Decode motion patterns for steps",
    },
    "energy_expenditure_0_0_10": {
        "category": "activity",
        "purpose": "Calorie burn estimation",
    },

    # Stress models
    "cumulative_stress_0_1_1": {
        "category": "stress",
        "purpose": "Daily cumulative stress score",
    },
    "stress_resilience_2_1_4": {
        "category": "stress",
        "purpose": "Stress resilience capacity",
    },
    "stress_daytime_sensing_1_0_4": {
        "category": "stress",
        "purpose": "Real-time daytime stress",
    },

    # Baseline models
    "daily_medians_1_0_2": {
        "category": "baselines",
        "purpose": "Personal baseline calculations",
    },
    "daily_short_term_baselines_1_0_1": {
        "category": "baselines",
        "purpose": "Short-term baseline tracking",
    },

    # Other health models
    "illness_detection_0_4_1": {
        "category": "health",
        "purpose": "Detect sickness onset",
    },
    "pregnancy_biometrics_0_4_0": {
        "category": "health",
        "purpose": "Pregnancy tracking metrics",
    },
    "meal_timing_0_0_5": {
        "category": "health",
        "purpose": "Detect meal consumption",
    },
    "popsicle_1_5_4": {
        "category": "health",
        "purpose": "Unknown (needs investigation)",
    },
}


def get_available_models(models_dir: Optional[Path] = None) -> List[ModelInfo]:
    """Get list of available models with metadata."""
    if models_dir is None:
        models_dir = DEFAULT_MODELS_DIR

    models = []
    for pt_file in models_dir.glob("*.pt"):
        name = pt_file.stem
        size = pt_file.stat().st_size

        # Parse version from filename (e.g., "sleepstaging_2_6_0" -> "2.6.0")
        parts = name.rsplit("_", 3)
        if len(parts) >= 4:
            base_name = "_".join(parts[:-3])
            version = f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
        else:
            base_name = name
            version = "unknown"

        # Get metadata from catalog
        meta = MODEL_CATALOG.get(name, {})
        category = meta.get("category", "unknown")
        purpose = meta.get("purpose", "Unknown purpose")

        models.append(ModelInfo(
            name=name,
            version=version,
            filename=pt_file.name,
            size_bytes=size,
            category=category,
            purpose=purpose,
        ))

    return sorted(models, key=lambda m: (m.category, m.name))


class ModelLoader:
    """
    Load and manage TorchScript models.

    Usage:
        loader = ModelLoader()
        model = loader.load("sleepstaging_2_6_0")
        output = model(input_tensor)
    """

    def __init__(self, models_dir: Optional[Path] = None, device: str = "cpu"):
        """
        Initialize the model loader.

        Args:
            models_dir: Directory containing .pt model files
            device: PyTorch device ("cpu" or "cuda")
        """
        if not TORCH_AVAILABLE:
            raise ImportError(
                "PyTorch is required for ML inference. "
                "Install with: pip install torch"
            )

        self.models_dir = Path(models_dir) if models_dir else DEFAULT_MODELS_DIR
        self.device = device
        self._loaded_models: Dict[str, Any] = {}

        if not self.models_dir.exists():
            raise FileNotFoundError(f"Models directory not found: {self.models_dir}")

        # Auto-register custom Oura ops (required for sleep staging models)
        self._register_custom_ops()

    def _register_custom_ops(self):
        """Register custom Oura TorchScript ops if not already registered."""
        try:
            from .custom_ops import register_oura_ops, is_registered
            if not is_registered():
                register_oura_ops()
        except ImportError:
            pass  # Custom ops module not available

    def list_models(self) -> List[ModelInfo]:
        """List all available models."""
        return get_available_models(self.models_dir)

    def list_by_category(self) -> Dict[str, List[ModelInfo]]:
        """List models grouped by category."""
        models = self.list_models()
        by_category: Dict[str, List[ModelInfo]] = {}
        for model in models:
            if model.category not in by_category:
                by_category[model.category] = []
            by_category[model.category].append(model)
        return by_category

    def get_model_path(self, model_name: str) -> Path:
        """Get the path to a model file."""
        # Try exact name first
        path = self.models_dir / f"{model_name}.pt"
        if path.exists():
            return path

        # Try without .pt extension
        if model_name.endswith(".pt"):
            path = self.models_dir / model_name
            if path.exists():
                return path

        raise FileNotFoundError(f"Model not found: {model_name}")

    def load(self, model_name: str, force_reload: bool = False) -> Any:
        """
        Load a TorchScript model.

        Args:
            model_name: Name of the model (without .pt extension)
            force_reload: Force reload even if cached

        Returns:
            Loaded TorchScript model
        """
        if model_name in self._loaded_models and not force_reload:
            return self._loaded_models[model_name]

        path = self.get_model_path(model_name)

        try:
            model = torch.jit.load(str(path), map_location=self.device)
            model.eval()  # Set to evaluation mode
            self._loaded_models[model_name] = model
            return model
        except Exception as e:
            raise RuntimeError(f"Failed to load model {model_name}: {e}")

    def unload(self, model_name: str) -> None:
        """Unload a model to free memory."""
        if model_name in self._loaded_models:
            del self._loaded_models[model_name]

    def unload_all(self) -> None:
        """Unload all models."""
        self._loaded_models.clear()

    def get_model_info(self, model_name: str) -> Optional[ModelInfo]:
        """Get metadata for a specific model."""
        for info in self.list_models():
            if info.name == model_name:
                return info
        return None

    def inspect_model(self, model_name: str) -> Dict[str, Any]:
        """
        Inspect a model's structure and graph.

        Returns dict with:
            - code: TorchScript code
            - graph: Model computation graph
            - parameters: Number of parameters
        """
        model = self.load(model_name)

        info = {
            "name": model_name,
            "type": type(model).__name__,
        }

        # Get TorchScript code if available
        if hasattr(model, "code"):
            info["code"] = model.code

        # Get computation graph
        if hasattr(model, "graph"):
            info["graph"] = str(model.graph)

        # Count parameters
        try:
            total_params = sum(
                p.numel() for p in model.parameters()
            )
            info["parameters"] = total_params
        except:
            info["parameters"] = "unknown"

        return info


def create_tensor(data, dtype=None) -> "torch.Tensor":
    """
    Create a PyTorch tensor from data.

    Args:
        data: Input data (list, numpy array, etc.)
        dtype: Optional dtype (defaults to float32)

    Returns:
        PyTorch tensor
    """
    if not TORCH_AVAILABLE:
        raise ImportError("PyTorch is required")

    if dtype is None:
        dtype = torch.float32

    return torch.tensor(data, dtype=dtype)


def to_numpy(tensor) -> Any:
    """Convert a PyTorch tensor to numpy array."""
    if not TORCH_AVAILABLE:
        raise ImportError("PyTorch is required")

    if isinstance(tensor, torch.Tensor):
        return tensor.detach().cpu().numpy()
    return tensor


# Convenience function
def load_model(model_name: str, models_dir: Optional[Path] = None) -> Any:
    """
    Quick helper to load a single model.

    Usage:
        model = load_model("sleepstaging_2_6_0")
    """
    loader = ModelLoader(models_dir=models_dir)
    return loader.load(model_name)
