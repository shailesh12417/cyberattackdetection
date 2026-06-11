from pathlib import Path
import sys


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.services.model_service import model_service
from app.services.training_service import DEFAULT_DATASET, train_model


if __name__ == "__main__":
    result = train_model(str(DEFAULT_DATASET), "label")
    model_service.refresh()
    metadata = result["metadata"]
    print("Training completed")
    print(f"Accuracy: {metadata['accuracy']}")
    print(f"Classes: {', '.join(metadata['classes'])}")
