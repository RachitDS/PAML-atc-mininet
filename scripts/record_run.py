"""Record the model selection actually passed to a new campaign."""
import hashlib
import json
import os
import sys
from pathlib import Path

root=Path(__file__).resolve().parents[1]
models=Path(os.environ['PAML_MODEL_DIR']).resolve()
try:
    directory=str(models.relative_to(root))
except ValueError:
    directory=str(models)
data=dict(mode=os.environ['PAML_MODE'],model_directory=directory,
          model_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in models.glob('paml_v4_*') if p.is_file()})
(Path(sys.argv[1])/'run_configuration.json').write_text(json.dumps(data,indent=2))
