"""
Module d'intégration des différents fournisseurs de LLM.
Supporte OpenAI, Anthropic (Claude), Cohere, DeepSeek et OpenRouter.
"""

import re
import html
import logging
import traceback
from typing import Any, Dict, List, Optional, Union, Callable

from resk_llm.tokenizer_protection import ReskWordsLists

# Configuration du logger
logger = logging.getLogger(__name__)

class BaseProviderProtector:
    """
    Classe de base pour les protecteurs de fournisseurs LLM.
    Implémente les fonctionnalités de base partagées par tous les fournisseurs.
    """
    def __init__(self, 
                 model: str,
                 preserved_prompts: int = 2,
                 request_sanitization: bool = True,
                 response_sanitization: bool = True):
        """
        Initialise le protecteur de base.
        
        Args:
            model: Nom du modèle à utiliser
            preserved_prompts: Nombre de messages système à préserver
            request_sanitization: Activer la désinfection des requêtes
            response_sanitization: Activer la désinfection des réponses
        """
        self.model = model
        self.preserved_prompts = preserved_prompts
        self.request_sanitization = request_sanitization
        self.response_sanitization = response_sanitization
        self.ReskWordsLists = ReskWordsLists()
        
    def sanitize_input(self, text: str) -> str:
        """
        Désinfecte un texte d'entrée.
        
        Args:
            text: Texte à désinfecter
            
        Returns:
            Texte désinfecté
        """
        # Encoder en UTF-8
        text = text.encode('utf-8', errors='ignore').decode('utf-8')

        # Supprimer les balises script
        text = re.sub(r'<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>', '', text)
        
        # Échapper les caractères HTML
        text = html.escape(text, quote=False)
        
        return text
    
    def check_malicious_content(self, text: str) -> Optional[str]:
        """
        Vérifie si un texte contient du contenu malveillant.
        
        Args:
            text: Texte à vérifier
            
        Returns:
            Message d'erreur si du contenu malveillant est détecté, None sinon
        """
        return self.ReskWordsLists.check_input(text)
    
    def update_prohibited_list(self, item: str, action: str, item_type: str) -> None:
        """
        Met à jour la liste des éléments interdits.
        
        Args:
            item: Élément à ajouter/supprimer
            action: Action à effectuer (add/remove)
            item_type: Type d'élément (word/pattern)
        """
        self.ReskWordsLists.update_prohibited_list(item, action, item_type)
    
    def log_error(self, message: str, error: Optional[Exception] = None) -> None:
        """
        Enregistre une erreur dans les logs.
        
        Args:
            message: Message d'erreur
            error: Exception (optionnel)
        """
        if error:
            logger.error(f"{message}: {str(error)}\n{traceback.format_exc()}")
        else:
            logger.error(message)


class OpenAIProtector(BaseProviderProtector):
    """
    Protecteur pour les modèles OpenAI (GPT).
    """
    def __init__(self, 
                 model: str = "gpt-4o",
                 preserved_prompts: int = 2,
                 request_sanitization: bool = True,
                 response_sanitization: bool = True,
                 max_tokens: int = 4096):
        """
        Initialise le protecteur OpenAI.
        
        Args:
            model: Modèle OpenAI à utiliser
            preserved_prompts: Nombre de messages système à préserver
            request_sanitization: Activer la désinfection des requêtes
            response_sanitization: Activer la désinfection des réponses
            max_tokens: Nombre maximum de tokens pour la réponse
        """
        super().__init__(
            model=model,
            preserved_prompts=preserved_prompts,
            request_sanitization=request_sanitization,
            response_sanitization=response_sanitization
        )
        self.max_tokens = max_tokens
        
        # Tokens spéciaux pour OpenAI
        self.special_tokens = set([
            "<|endoftext|>", "<|fim_prefix|>", "<|fim_middle|>", "<|fim_suffix|>",
            "<|endofprompt|>", "<s>", "</s>", "<|im_start|>", "<|im_end|>", "<|im_sep|>"
        ])
    
    def sanitize_input(self, text: str) -> str:
        """
        Désinfecte un texte d'entrée spécifiquement pour OpenAI.
        
        Args:
            text: Texte à désinfecter
            
        Returns:
            Texte désinfecté
        """
        # Appliquer le nettoyage de base
        text = super().sanitize_input(text)
        
        # Supprimer les tokens spéciaux d'OpenAI
        for token in self.special_tokens:
            text = text.replace(token, "")
            
        return text
    
    def protect_openai_call(self, api_function: Callable, messages: List[Dict[str, str]], 
                           chat_history: Optional[List[Dict[str, str]]] = None, **kwargs: Any) -> Any:
        """
        Protège un appel à l'API OpenAI.
        
        Args:
            api_function: Fonction API à appeler
            messages: Liste des messages à envoyer
            chat_history: Historique du chat (optionnel)
            kwargs: Arguments nommés supplémentaires
            
        Returns:
            Résultat de l'appel API
        """
        if chat_history is None:
            chat_history = []
        
        try:
            # Désinfecter les messages si la désinfection est activée
            if self.request_sanitization:
                sanitized_messages = []
                for message in messages:
                    content = message.get('content', '')
                    if isinstance(content, str):
                        sanitized_content = self.sanitize_input(content)
                        
                        # Vérifier le contenu malveillant
                        warning = self.check_malicious_content(sanitized_content)
                        if warning:
                            return {"error": warning}
                        
                        sanitized_messages.append({**message, "content": sanitized_content})
                    else:
                        # Gérer les contenus multi-modaux
                        sanitized_content = []
                        for item in content:
                            if isinstance(item, dict):
                                if item.get('type') == 'text':
                                    text = item.get('text', '')
                                    sanitized_text = self.sanitize_input(text)
                                    
                                    # Vérifier le contenu malveillant
                                    warning = self.check_malicious_content(sanitized_text)
                                    if warning:
                                        return {"error": warning}
                                    
                                    sanitized_content.append({**item, 'text': sanitized_text})
                                else:
                                    sanitized_content.append(item)
                            else:
                                sanitized_content.append(item)
                        
                        sanitized_messages.append({**message, "content": sanitized_content})
                
                # Remplacer les messages originaux par les messages désinfectés
                kwargs['messages'] = sanitized_messages
            else:
                kwargs['messages'] = messages
            
            # Définir le modèle et les tokens maximum
            kwargs['model'] = self.model
            kwargs['max_tokens'] = kwargs.get('max_tokens', self.max_tokens)
            
            # Appeler l'API
            response = api_function(**kwargs)
            
            # Désinfecter la réponse si nécessaire
            if self.response_sanitization and hasattr(response, 'choices') and len(response.choices) > 0:
                if hasattr(response.choices[0], 'message') and hasattr(response.choices[0].message, 'content'):
                    content = response.choices[0].message.content
                    if content:
                        response.choices[0].message.content = self.sanitize_input(content)
            
            return response
            
        except Exception as e:
            self.log_error("Erreur lors de l'appel à l'API OpenAI", e)
            return {"error": "Une erreur s'est produite lors du traitement de votre demande."}


class AnthropicProtector(BaseProviderProtector):
    """
    Protecteur pour les modèles Anthropic (Claude).
    """
    def __init__(self, 
                 model: str = "claude-3-opus-20240229",
                 preserved_prompts: int = 2,
                 request_sanitization: bool = True,
                 response_sanitization: bool = True,
                 max_tokens: int = 4096):
        """
        Initialise le protecteur Anthropic.
        
        Args:
            model: Modèle Anthropic à utiliser
            preserved_prompts: Nombre de messages système à préserver
            request_sanitization: Activer la désinfection des requêtes
            response_sanitization: Activer la désinfection des réponses
            max_tokens: Nombre maximum de tokens pour la réponse
        """
        super().__init__(
            model=model,
            preserved_prompts=preserved_prompts,
            request_sanitization=request_sanitization,
            response_sanitization=response_sanitization
        )
        self.max_tokens = max_tokens
        
        # Tokens spéciaux pour Anthropic
        self.special_tokens = set([
            "<human>", "</human>", 
            "<assistant>", "</assistant>",
            "<system>", "</system>",
            "<answer>", "</answer>",
            "<message>", "</message>"
        ])
    
    def sanitize_input(self, text: str) -> str:
        """
        Désinfecte un texte d'entrée spécifiquement pour Anthropic.
        
        Args:
            text: Texte à désinfecter
            
        Returns:
            Texte désinfecté
        """
        # Appliquer le nettoyage de base
        text = super().sanitize_input(text)
        
        # Supprimer les tokens spéciaux d'Anthropic
        for token in self.special_tokens:
            text = text.replace(token, "")
            
        return text
    
    def protect_anthropic_call(self, api_function: Callable, messages: List[Dict[str, str]], *args: Any, **kwargs: Any) -> Any:
        """
        Protège un appel à l'API Anthropic.
        
        Args:
            api_function: Fonction API à appeler
            messages: Liste des messages à envoyer
            args: Arguments positionnels supplémentaires
            kwargs: Arguments nommés supplémentaires
            
        Returns:
            Résultat de l'appel API
        """
        try:
            # Désinfecter les messages si la désinfection est activée
            if self.request_sanitization:
                sanitized_messages = []
                for message in messages:
                    content = message.get('content', '')
                    if isinstance(content, str):
                        sanitized_content = self.sanitize_input(content)
                        
                        # Vérifier le contenu malveillant
                        warning = self.check_malicious_content(sanitized_content)
                        if warning:
                            return {"error": warning}
                        
                        sanitized_messages.append({**message, "content": sanitized_content})
                    else:
                        # Gérer les contenus multi-modaux
                        sanitized_content = []
                        for item in content:
                            if isinstance(item, dict):
                                if item.get('type') == 'text':
                                    text = item.get('text', '')
                                    sanitized_text = self.sanitize_input(text)
                                    
                                    # Vérifier le contenu malveillant
                                    warning = self.check_malicious_content(sanitized_text)
                                    if warning:
                                        return {"error": warning}
                                    
                                    sanitized_content.append({**item, 'text': sanitized_text})
                                else:
                                    sanitized_content.append(item)
                            else:
                                sanitized_content.append(item)
                        
                        sanitized_messages.append({**message, "content": sanitized_content})
                
                # Remplacer les messages originaux par les messages désinfectés
                kwargs['messages'] = sanitized_messages
            else:
                kwargs['messages'] = messages
            
            # Définir le modèle et les tokens maximum
            kwargs['model'] = self.model
            kwargs['max_tokens'] = kwargs.get('max_tokens', self.max_tokens)
            
            # Appeler l'API
            response = api_function(*args, **kwargs)
            
            # Désinfecter la réponse si nécessaire
            if self.response_sanitization and hasattr(response, 'content'):
                response.content = self.sanitize_input(response.content)
            
            return response
            
        except Exception as e:
            self.log_error("Erreur lors de l'appel à l'API Anthropic", e)
            return {"error": "Une erreur s'est produite lors du traitement de votre demande."}


class CohereProtector(BaseProviderProtector):
    """
    Protecteur pour les modèles Cohere.
    """
    def __init__(self, 
                 model: str = "command-r-plus",
                 preserved_prompts: int = 2,
                 request_sanitization: bool = True,
                 response_sanitization: bool = True,
                 max_tokens: int = 2048):
        """
        Initialise le protecteur Cohere.
        
        Args:
            model: Modèle Cohere à utiliser
            preserved_prompts: Nombre de messages système à préserver
            request_sanitization: Activer la désinfection des requêtes
            response_sanitization: Activer la désinfection des réponses
            max_tokens: Nombre maximum de tokens pour la réponse
        """
        super().__init__(
            model=model,
            preserved_prompts=preserved_prompts,
            request_sanitization=request_sanitization,
            response_sanitization=response_sanitization
        )
        self.max_tokens = max_tokens
    
    def protect_cohere_call(self, api_function: Callable, message: str, *args: Any, **kwargs: Any) -> Any:
        """
        Protège un appel à l'API Cohere.
        
        Args:
            api_function: Fonction API à appeler
            message: Message à envoyer
            args: Arguments positionnels supplémentaires
            kwargs: Arguments nommés supplémentaires
            
        Returns:
            Résultat de l'appel API
        """
        try:
            # Désinfecter le message si la désinfection est activée
            if self.request_sanitization:
                sanitized_message = self.sanitize_input(message)
                
                # Vérifier le contenu malveillant
                warning = self.check_malicious_content(sanitized_message)
                if warning:
                    return {"error": warning}
                
                # Remplacer le message original par le message désinfecté
                kwargs['message'] = sanitized_message
            else:
                kwargs['message'] = message
            
            # Définir le modèle et les tokens maximum
            kwargs['model'] = self.model
            kwargs['max_tokens'] = kwargs.get('max_tokens', self.max_tokens)
            
            # Appeler l'API
            response = api_function(*args, **kwargs)
            
            # Désinfecter la réponse si nécessaire
            if self.response_sanitization and hasattr(response, 'text'):
                response.text = self.sanitize_input(response.text)
            
            return response
            
        except Exception as e:
            self.log_error("Erreur lors de l'appel à l'API Cohere", e)
            return {"error": "Une erreur s'est produite lors du traitement de votre demande."}
    
    def protect_cohere_chat_call(self, api_function: Callable, message: str, chat_history: Optional[List[Dict[str, str]]] = None, *args: Any, **kwargs: Any) -> Any:
        """
        Protège un appel à l'API Cohere Chat.
        
        Args:
            api_function: Fonction API à appeler
            message: Message à envoyer
            chat_history: Historique du chat (optionnel)
            args: Arguments positionnels supplémentaires
            kwargs: Arguments nommés supplémentaires
            
        Returns:
            Résultat de l'appel API
        """
        try:
            # Désinfecter le message si la désinfection est activée
            if self.request_sanitization:
                sanitized_message = self.sanitize_input(message)
                
                # Vérifier le contenu malveillant
                warning = self.check_malicious_content(sanitized_message)
                if warning:
                    return {"error": warning}
                
                # Remplacer le message original par le message désinfecté
                kwargs['message'] = sanitized_message
                
                # Désinfecter l'historique du chat si présent
                if chat_history:
                    sanitized_history = []
                    for msg in chat_history:
                        role = msg.get('role', '')
                        content = msg.get('message', '')
                        sanitized_content = self.sanitize_input(content)
                        
                        # Vérifier le contenu malveillant
                        warning = self.check_malicious_content(sanitized_content)
                        if warning:
                            return {"error": warning}
                        
                        sanitized_history.append({
                            'role': role,
                            'message': sanitized_content
                        })
                    
                    kwargs['chat_history'] = sanitized_history
            else:
                kwargs['message'] = message
                if chat_history:
                    kwargs['chat_history'] = chat_history
            
            # Définir le modèle
            kwargs['model'] = self.model
            
            # Appeler l'API
            response = api_function(*args, **kwargs)
            
            # Désinfecter la réponse si nécessaire
            if self.response_sanitization and hasattr(response, 'text'):
                response.text = self.sanitize_input(response.text)
            
            return response
            
        except Exception as e:
            self.log_error("Erreur lors de l'appel à l'API Cohere Chat", e)
            return {"error": "Une erreur s'est produite lors du traitement de votre demande."}


class DeepSeekProtector(BaseProviderProtector):
    """
    Protecteur pour les modèles DeepSeek.
    """
    def __init__(self, 
                 model: str = "deepseek-chat",
                 preserved_prompts: int = 2,
                 request_sanitization: bool = True,
                 response_sanitization: bool = True,
                 max_tokens: int = 4096):
        """
        Initialise le protecteur DeepSeek.
        
        Args:
            model: Modèle DeepSeek à utiliser
            preserved_prompts: Nombre de messages système à préserver
            request_sanitization: Activer la désinfection des requêtes
            response_sanitization: Activer la désinfection des réponses
            max_tokens: Nombre maximum de tokens pour la réponse
        """
        super().__init__(
            model=model,
            preserved_prompts=preserved_prompts,
            request_sanitization=request_sanitization,
            response_sanitization=response_sanitization
        )
        self.max_tokens = max_tokens
        
        # Tokens spéciaux pour DeepSeek
        self.special_tokens = set([
            "<|im_start|>", "<|im_end|>",
            "<|user|>", "<|assistant|>", "<|system|>"
        ])
    
    def sanitize_input(self, text: str) -> str:
        """
        Désinfecte un texte d'entrée spécifiquement pour DeepSeek.
        
        Args:
            text: Texte à désinfecter
            
        Returns:
            Texte désinfecté
        """
        # Appliquer le nettoyage de base
        text = super().sanitize_input(text)
        
        # Supprimer les tokens spéciaux de DeepSeek
        for token in self.special_tokens:
            text = text.replace(token, "")
            
        return text
    
    def protect_deepseek_call(self, api_function: Callable, messages: List[Dict[str, str]], *args: Any, **kwargs: Any) -> Any:
        """
        Protège un appel à l'API DeepSeek.
        
        Args:
            api_function: Fonction API à appeler
            messages: Liste des messages à envoyer
            args: Arguments positionnels supplémentaires
            kwargs: Arguments nommés supplémentaires
            
        Returns:
            Résultat de l'appel API
        """
        try:
            # Désinfecter les messages si la désinfection est activée
            if self.request_sanitization:
                sanitized_messages = []
                for message in messages:
                    content = message.get('content', '')
                    sanitized_content = self.sanitize_input(content)
                    
                    # Vérifier le contenu malveillant
                    warning = self.check_malicious_content(sanitized_content)
                    if warning:
                        return {"error": warning}
                    
                    sanitized_messages.append({**message, "content": sanitized_content})
                
                # Remplacer les messages originaux par les messages désinfectés
                kwargs['messages'] = sanitized_messages
            else:
                kwargs['messages'] = messages
            
            # Définir le modèle et les tokens maximum
            kwargs['model'] = self.model
            kwargs['max_tokens'] = kwargs.get('max_tokens', self.max_tokens)
            
            # Appeler l'API
            response = api_function(*args, **kwargs)
            
            # Désinfecter la réponse si nécessaire
            if self.response_sanitization and hasattr(response, 'choices') and len(response.choices) > 0:
                response.choices[0].message.content = self.sanitize_input(response.choices[0].message.content)
            
            return response
            
        except Exception as e:
            self.log_error("Erreur lors de l'appel à l'API DeepSeek", e)
            return {"error": "Une erreur s'est produite lors du traitement de votre demande."}


class OpenRouterProtector(BaseProviderProtector):
    """
    Protecteur pour les modèles via OpenRouter.
    """
    def __init__(self, 
                 model: str = "anthropic/claude-3-opus",
                 preserved_prompts: int = 2,
                 request_sanitization: bool = True,
                 response_sanitization: bool = True,
                 max_tokens: int = 4096):
        """
        Initialise le protecteur OpenRouter.
        
        Args:
            model: Modèle OpenRouter à utiliser
            preserved_prompts: Nombre de messages système à préserver
            request_sanitization: Activer la désinfection des requêtes
            response_sanitization: Activer la désinfection des réponses
            max_tokens: Nombre maximum de tokens pour la réponse
        """
        super().__init__(
            model=model,
            preserved_prompts=preserved_prompts,
            request_sanitization=request_sanitization,
            response_sanitization=response_sanitization
        )
        self.max_tokens = max_tokens
        
        # Tous les tokens spéciaux potentiels des différents modèles
        self.special_tokens = set([
            "<|endoftext|>", "<|fim_prefix|>", "<|fim_middle|>", "<|fim_suffix|>",
            "<|endofprompt|>", "<s>", "</s>", "<|im_start|>", "<|im_end|>", "<|im_sep|>",
            "[/INST]", "SYS", "[INST]", "<endoftext>", "</endoftext>", "<|end|>",
            "Human:", "Assistant:", "<human>", "</human>", "<assistant>", "</assistant>",
            "<system>", "</system>", "<answer>", "</answer>", "<message>", "</message>",
            "<|user|>", "<|assistant|>", "<|system|>"
        ])
    
    def sanitize_input(self, text: str) -> str:
        """
        Désinfecte un texte d'entrée pour tous les modèles possibles via OpenRouter.
        
        Args:
            text: Texte à désinfecter
            
        Returns:
            Texte désinfecté
        """
        # Appliquer le nettoyage de base
        text = super().sanitize_input(text)
        
        # Supprimer tous les tokens spéciaux
        for token in self.special_tokens:
            text = text.replace(token, "")
            
        return text
    
    def protect_openrouter_call(self, api_function: Callable, messages: List[Dict[str, str]], *args: Any, **kwargs: Any) -> Any:
        """
        Protège un appel à l'API OpenRouter.
        
        Args:
            api_function: Fonction API à appeler
            messages: Liste des messages à envoyer
            args: Arguments positionnels supplémentaires
            kwargs: Arguments nommés supplémentaires
            
        Returns:
            Résultat de l'appel API
        """
        try:
            # Désinfecter les messages si la désinfection est activée
            if self.request_sanitization:
                sanitized_messages = []
                for message in messages:
                    content = message.get('content', '')
                    sanitized_content = self.sanitize_input(content)
                    
                    # Vérifier le contenu malveillant
                    warning = self.check_malicious_content(sanitized_content)
                    if warning:
                        return {"error": warning}
                    
                    sanitized_messages.append({**message, "content": sanitized_content})
                
                # Remplacer les messages originaux par les messages désinfectés
                kwargs['messages'] = sanitized_messages
            else:
                kwargs['messages'] = messages
            
            # Définir le modèle et les tokens maximum
            kwargs['model'] = self.model
            kwargs['max_tokens'] = kwargs.get('max_tokens', self.max_tokens)
            
            # Appeler l'API
            response = api_function(*args, **kwargs)
            
            # Désinfecter la réponse si nécessaire
            if self.response_sanitization and hasattr(response, 'choices') and len(response.choices) > 0:
                response.choices[0].message.content = self.sanitize_input(response.choices[0].message.content)
            
            return response
            
        except Exception as e:
            self.log_error("Erreur lors de l'appel à l'API OpenRouter", e)
            return {"error": "Une erreur s'est produite lors du traitement de votre demande."} 