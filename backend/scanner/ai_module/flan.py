import os
import threading

from transformers import AutoTokenizer, AutoModelForSeq2SeqLM

# Chargement paresseux et partagé du modèle Flan-T5.
# VulnRecommender et ChatbotRAG réutilisent la même instance afin de ne pas
# charger le modèle deux fois en mémoire.
_lock = threading.Lock()
_tokenizer = None
_model = None


def _resolve_model_path():
    # ai_module/flan.py → dossier local optionnel ai_module/flan_model
    module_dir = os.path.dirname(os.path.abspath(__file__))
    model_path = os.path.join(module_dir, 'flan_model')

    if not os.path.isdir(model_path):
        model_path = "google/flan-t5-base"

    return model_path


def get_flan_model():
    """Retourne (tokenizer, model) Flan-T5, chargés une seule fois (singleton)."""
    global _tokenizer, _model
    if _model is None or _tokenizer is None:
        with _lock:
            if _model is None or _tokenizer is None:
                model_path = _resolve_model_path()
                _tokenizer = AutoTokenizer.from_pretrained(model_path)
                _model = AutoModelForSeq2SeqLM.from_pretrained(model_path)
                # eval() désactive le dropout pour des réponses plus stables
                _model.eval()
    return _tokenizer, _model
