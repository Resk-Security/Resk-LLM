import re
import html
import logging
import traceback
from typing import Any, Dict, List, Optional, Union, Callable

from resk_llm.openai_protector import OpenAIProtector
from resk_llm.tokenizer_protection import SecureTokenizer, TokenizerProtector

# Configuration du logger
logger = logging.getLogger(__name__)

class HuggingFaceProtector:
    """
    Protecteur pour les modèles et pipelines Hugging Face.
    Ajoute une couche de sécurité pour les modèles de langage, d'image et multimodaux.
    """
    def __init__(self, 
                 use_openai_protection: bool = True,
                 model: str = "gpt-4o", 
                 max_tokens: int = 1024,
                 sanitize_outputs: bool = True):
        """
        Initialise le protecteur Hugging Face.
        
        Args:
            use_openai_protection: Utiliser la protection OpenAI pour les LLM
            model: Modèle OpenAI à utiliser si use_openai_protection est True
            max_tokens: Nombre maximum de tokens à traiter
            sanitize_outputs: Nettoyer les sorties des modèles
        """
        self.use_openai_protection = use_openai_protection
        if use_openai_protection:
            self.protector = OpenAIProtector(model=model)
        self.max_tokens = max_tokens
        self.sanitize_outputs = sanitize_outputs
        
    def secure_tokenizer(self, tokenizer):
        """
        Sécurise un tokenizer Hugging Face.
        
        Args:
            tokenizer: Tokenizer Hugging Face à sécuriser
            
        Returns:
            TokenizerProtector sécurisé
        """
        return TokenizerProtector(tokenizer)
    
    def secure_pipeline(self, pipeline):
        """
        Sécurise un pipeline Hugging Face.
        
        Args:
            pipeline: Pipeline Hugging Face à sécuriser
            
        Returns:
            Pipeline sécurisé
        """
        original_call = pipeline.__call__
        
        # Méthode sécurisée pour le pipeline
        def secure_pipeline_call(texts, *args, **kwargs):
            try:
                # Nettoyer les entrées
                if isinstance(texts, str):
                    cleaned_text = self._sanitize_text(texts)
                    
                    # Vérifier les motifs malveillants si la protection OpenAI est activée
                    if self.use_openai_protection:
                        warning = self.protector.ReskWordsLists.check_input(cleaned_text)
                        if warning:
                            logger.warning(f"Tentative d'injection détectée: {warning}")
                            return {"error": warning}
                            
                    texts = cleaned_text
                elif isinstance(texts, list):
                    cleaned_texts = []
                    for text in texts:
                        if isinstance(text, str):
                            cleaned_text = self._sanitize_text(text)
                            
                            # Vérifier les motifs malveillants si la protection OpenAI est activée
                            if self.use_openai_protection:
                                warning = self.protector.ReskWordsLists.check_input(cleaned_text)
                                if warning:
                                    logger.warning(f"Tentative d'injection détectée: {warning}")
                                    return {"error": warning}
                                    
                            cleaned_texts.append(cleaned_text)
                        else:
                            cleaned_texts.append(text)
                    texts = cleaned_texts
                
                # Appel sécurisé au pipeline original
                result = original_call(texts, *args, **kwargs)
                
                # Nettoyer les sorties si nécessaire
                if self.sanitize_outputs:
                    result = self._sanitize_output(result)
                
                return result
            except Exception as e:
                logger.error(f"Erreur dans secure_pipeline_call: {str(e)}\n{traceback.format_exc()}")
                return {"error": "Une erreur s'est produite lors du traitement de votre demande."}
        
        # Remplacer la méthode originale
        pipeline.__call__ = secure_pipeline_call
        
        return pipeline
    
    def secure_model(self, model, tokenizer=None):
        """
        Sécurise un modèle Hugging Face.
        
        Args:
            model: Modèle Hugging Face à sécuriser
            tokenizer: Tokenizer associé au modèle
            
        Returns:
            Modèle sécurisé
        """
        # Sécuriser le tokenizer si fourni
        if tokenizer:
            secure_tokenizer = self.secure_tokenizer(tokenizer)
        
        # Sauvegarder les méthodes originales
        original_generate = getattr(model, "generate", None)
        original_forward = getattr(model, "forward", None)
        
        # Sécuriser la méthode generate si elle existe
        if original_generate:
            def secure_generate(input_ids=None, attention_mask=None, *args, **kwargs):
                try:
                    # Limiter la taille de sortie
                    if "max_length" not in kwargs:
                        kwargs["max_length"] = self.max_tokens
                    elif kwargs["max_length"] > self.max_tokens * 2:
                        kwargs["max_length"] = self.max_tokens * 2
                    
                    # Éviter les répétitions infinies
                    if "repetition_penalty" not in kwargs:
                        kwargs["repetition_penalty"] = 1.2
                    
                    # Exécuter la méthode originale
                    result = original_generate(input_ids=input_ids, attention_mask=attention_mask, *args, **kwargs)
                    
                    return result
                except Exception as e:
                    logger.error(f"Erreur dans secure_generate: {str(e)}\n{traceback.format_exc()}")
                    return None
            
            # Remplacer la méthode originale
            model.generate = secure_generate
        
        # Sécuriser la méthode forward si elle existe
        if original_forward:
            def secure_forward(*args, **kwargs):
                try:
                    # Vérifier et nettoyer les entrées
                    if "input_ids" in kwargs and hasattr(kwargs["input_ids"], "shape"):
                        if kwargs["input_ids"].shape[1] > self.max_tokens:
                            logger.warning(f"Troncature des entrées trop longues: {kwargs['input_ids'].shape[1]} > {self.max_tokens}")
                            kwargs["input_ids"] = kwargs["input_ids"][:, :self.max_tokens]
                    
                    # Exécuter la méthode originale
                    result = original_forward(*args, **kwargs)
                    
                    return result
                except Exception as e:
                    logger.error(f"Erreur dans secure_forward: {str(e)}\n{traceback.format_exc()}")
                    return None
            
            # Remplacer la méthode originale
            model.forward = secure_forward
        
        return model
    
    def _sanitize_text(self, text: str) -> str:
        """
        Nettoie un texte d'entrée.
        
        Args:
            text: Texte à nettoyer
            
        Returns:
            Texte nettoyé
        """
        if self.use_openai_protection:
            return self.protector.sanitize_input(text)
        
        # Nettoyage de base si la protection OpenAI n'est pas utilisée
        text = text.encode('utf-8', errors='ignore').decode('utf-8')
        text = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', text)
        text = html.escape(text, quote=False)
        return text
    
    def _sanitize_output(self, output: Any) -> Any:
        """
        Nettoie une sortie de modèle.
        
        Args:
            output: Sortie à nettoyer
            
        Returns:
            Sortie nettoyée
        """
        if isinstance(output, str):
            return self._sanitize_text(output)
        elif isinstance(output, list):
            return [self._sanitize_output(item) for item in output]
        elif isinstance(output, dict):
            return {key: self._sanitize_output(value) for key, value in output.items()}
        else:
            return output


class MultiModalProtector:
    """
    Protecteur spécialisé pour les modèles multimodaux, incluant la sécurité
    des entrées texte, image et audio.
    """
    def __init__(self, 
                 use_openai_protection: bool = True,
                 model: str = "gpt-4o", 
                 max_tokens: int = 1024,
                 image_content_filtering: bool = True,
                 audio_content_filtering: bool = True):
        """
        Initialise le protecteur multimodal.
        
        Args:
            use_openai_protection: Utiliser la protection OpenAI pour les LLM
            model: Modèle OpenAI à utiliser si use_openai_protection est True
            max_tokens: Nombre maximum de tokens à traiter
            image_content_filtering: Activer le filtrage du contenu des images
            audio_content_filtering: Activer le filtrage du contenu audio
        """
        self.hf_protector = HuggingFaceProtector(
            use_openai_protection=use_openai_protection,
            model=model,
            max_tokens=max_tokens
        )
        self.image_content_filtering = image_content_filtering
        self.audio_content_filtering = audio_content_filtering
    
    def secure_vision_model(self, model, processor=None):
        """
        Sécurise un modèle de vision.
        
        Args:
            model: Modèle de vision à sécuriser
            processor: Processeur associé au modèle
            
        Returns:
            Modèle sécurisé
        """
        # Sécuriser le processeur si fourni
        if processor:
            original_process = processor.__call__
            
            def secure_process(images=None, text=None, *args, **kwargs):
                try:
                    # Nettoyer le texte si présent
                    if text is not None:
                        if isinstance(text, str):
                            text = self.hf_protector._sanitize_text(text)
                        elif isinstance(text, list):
                            text = [
                                self.hf_protector._sanitize_text(t) if isinstance(t, str) else t
                                for t in text
                            ]
                    
                    # Filtrer les images si activé
                    if self.image_content_filtering and images is not None:
                        # Le filtrage d'image réel nécessiterait un modèle de détection
                        # Ici, nous nous contentons d'un message de log
                        logger.info("Filtrage d'image appliqué (simulation)")
                    
                    # Exécuter la méthode originale
                    result = original_process(images=images, text=text, *args, **kwargs)
                    
                    return result
                except Exception as e:
                    logger.error(f"Erreur dans secure_process: {str(e)}\n{traceback.format_exc()}")
                    return None
            
            # Remplacer la méthode originale
            processor.__call__ = secure_process
        
        # Sécuriser le modèle lui-même
        return self.hf_protector.secure_model(model)
    
    def secure_audio_model(self, model, processor=None):
        """
        Sécurise un modèle audio.
        
        Args:
            model: Modèle audio à sécuriser
            processor: Processeur associé au modèle
            
        Returns:
            Modèle sécurisé
        """
        # Sécuriser le processeur si fourni
        if processor:
            original_process = processor.__call__
            
            def secure_audio_process(audio=None, text=None, *args, **kwargs):
                try:
                    # Nettoyer le texte si présent
                    if text is not None:
                        if isinstance(text, str):
                            text = self.hf_protector._sanitize_text(text)
                        elif isinstance(text, list):
                            text = [
                                self.hf_protector._sanitize_text(t) if isinstance(t, str) else t
                                for t in text
                            ]
                    
                    # Filtrer l'audio si activé
                    if self.audio_content_filtering and audio is not None:
                        # Le filtrage audio réel nécessiterait un modèle spécifique
                        # Ici, nous nous contentons d'un message de log
                        logger.info("Filtrage audio appliqué (simulation)")
                    
                    # Exécuter la méthode originale
                    result = original_process(audio=audio, text=text, *args, **kwargs)
                    
                    return result
                except Exception as e:
                    logger.error(f"Erreur dans secure_audio_process: {str(e)}\n{traceback.format_exc()}")
                    return None
            
            # Remplacer la méthode originale
            processor.__call__ = secure_audio_process
        
        # Sécuriser le modèle lui-même
        return self.hf_protector.secure_model(model) 