from typing import Dict, List, Union, Optional, Any, Tuple
import re
import json
import time
import logging
from collections import deque

# Configuration du logger
logger = logging.getLogger(__name__)

class TextCleaner:
    """
    Classe pour nettoyer le texte.
    """
    @staticmethod
    def clean_text(text: str) -> str:
        """
        Nettoie un texte en normalisant les espaces.
        
        Args:
            text: Texte à nettoyer
            
        Returns:
            Texte nettoyé
        """
        return ' '.join(text.split())

    @staticmethod
    def truncate_text(text: str, max_length: int) -> str:
        """
        Tronque un texte à une longueur maximale.
        
        Args:
            text: Texte à tronquer
            max_length: Longueur maximale
            
        Returns:
            Texte tronqué
        """
        if len(text) <= max_length:
            return text
        
        # Essayer de tronquer au dernier espace pour éviter de couper un mot
        last_space = text[:max_length].rfind(' ')
        if last_space > max_length * 0.8:  # Si on perd moins de 20% du texte
            return text[:last_space] + "..."
        
        return text[:max_length] + "..."
    
    @staticmethod
    def remove_duplicate_lines(text: str) -> str:
        """
        Supprime les lignes dupliquées consécutives.
        
        Args:
            text: Texte à nettoyer
            
        Returns:
            Texte nettoyé
        """
        lines = text.split('\n')
        result = []
        prev_line = None
        
        for line in lines:
            if line != prev_line:
                result.append(line)
                prev_line = line
                
        return '\n'.join(result)
    
    @staticmethod
    def format_code_blocks(text: str) -> str:
        """
        Formate correctement les blocs de code.
        
        Args:
            text: Texte à formater
            
        Returns:
            Texte formaté
        """
        # Assurer que les blocs de code ont des délimiteurs corrects
        code_block_pattern = r'```(?:\w+)?\n(.*?)\n```'
        
        def fix_code_block(match):
            content = match.group(1)
            if not content.endswith('\n'):
                content += '\n'
            return f'```\n{content}```'
        
        return re.sub(code_block_pattern, fix_code_block, text, flags=re.DOTALL)

class ContextManagerBase:
    """
    Classe de base pour les gestionnaires de contexte.
    """
    def __init__(self, model_info: Dict[str, Union[int, str]], preserved_prompts: int = 2):
        """
        Initialise le gestionnaire de contexte de base.
        
        Args:
            model_info: Informations sur le modèle
            preserved_prompts: Nombre de prompts à préserver
        """
        self.max_context_length = int(model_info.get("context_window", 8192))
        self.preserved_prompts = preserved_prompts
        self.text_cleaner = TextCleaner()
        self.logger = logging.getLogger(__name__)
        
    def clean_message(self, message: str) -> str:
        """
        Nettoie un message.
        
        Args:
            message: Message à nettoyer
            
        Returns:
            Message nettoyé
        """
        message = self.text_cleaner.clean_text(message)
        message = self.text_cleaner.remove_duplicate_lines(message)
        message = self.text_cleaner.format_code_blocks(message)
        message = self._close_html_tags(message)
        return message

    def _close_html_tags(self, text: str) -> str:
        """
        Ferme les balises HTML ouvertes dans un texte.
        
        Args:
            text: Texte avec potentiellement des balises non fermées
            
        Returns:
            Texte avec balises fermées
        """
        opened_tags: List[str] = []
        # Trouver toutes les balises ouvertes et fermées
        for match in re.finditer(r'<(/)?(\w+)[^>]*>', text):
            is_closing = match.group(1) is not None
            tag = match.group(2).lower()
            
            # Ignorer les tags auto-fermants
            if tag.lower() in ['br', 'hr', 'img', 'input', 'meta', 'link']:
                continue
                
            if is_closing:
                # Si c'est une balise fermante, vérifier qu'elle correspond à la dernière balise ouverte
                if opened_tags and opened_tags[-1] == tag:
                    opened_tags.pop()
                # Sinon, c'est une balise fermante sans ouvrante correspondante
            else:
                # Ajouter la balise à la liste des balises ouvertes
                opened_tags.append(tag)
                
        # Fermer les balises restantes dans l'ordre inverse
        for tag in reversed(opened_tags):
            text += f'</{tag}>'
            
        return text
    
    def estimate_tokens(self, text: str) -> int:
        """
        Estime le nombre de tokens dans un texte.
        C'est une approximation basée sur le nombre de mots.
        
        Args:
            text: Texte à analyser
            
        Returns:
            Nombre estimé de tokens
        """
        words = text.split()
        return int(len(words) * 1.3)  # Un token est généralement ~0.75 mots
    
    def _get_message_tokens(self, message: Dict[str, str]) -> int:
        """
        Estime le nombre de tokens dans un message.
        
        Args:
            message: Message à analyser
            
        Returns:
            Nombre estimé de tokens
        """
        content = message.get('content', '')
        role = message.get('role', '')
        
        if isinstance(content, list):  # Format multimodal
            text_content = ""
            for item in content:
                if isinstance(item, dict) and item.get('type') == 'text':
                    text_content += item.get('text', '')
            content = text_content
            
        return self.estimate_tokens(content) + self.estimate_tokens(role) + 4  # +4 pour les tokens de structure


class TokenBasedContextManager(ContextManagerBase):
    """
    Gestionnaire de contexte basé sur le nombre de tokens.
    """
    def __init__(self, 
                 model_info: Dict[str, Union[int, str]], 
                 preserved_prompts: int = 2, 
                 reserved_tokens: int = 1000,
                 compression_enabled: bool = False):
        """
        Initialise le gestionnaire de contexte basé sur les tokens.
        
        Args:
            model_info: Informations sur le modèle
            preserved_prompts: Nombre de prompts à préserver
            reserved_tokens: Nombre de tokens réservés pour la réponse
            compression_enabled: Activer la compression du contexte
        """
        super().__init__(model_info, preserved_prompts)
        self.reserved_tokens = reserved_tokens
        self.compression_enabled = compression_enabled
        self.token_estimator = self.estimate_tokens

    def manage_sliding_context(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Gère le contexte glissant, en préservant les messages importants et en tronquant si nécessaire.
        
        Args:
            messages: Liste des messages
            
        Returns:
            Liste des messages ajustée
        """
        # Nettoyer les messages et estimer leur taille en tokens
        cleaned_messages = []
        total_tokens = 0
        
        for msg in messages:
            content = msg.get('content', '')
            role = msg.get('role', '')
            
            if isinstance(content, str):
                cleaned_content = self.clean_message(content)
                message_tokens = self.token_estimator(cleaned_content) + self.token_estimator(role) + 4
                cleaned_messages.append({
                    'role': role, 
                    'content': cleaned_content, 
                    'tokens': message_tokens
                })
                total_tokens += message_tokens
            else:  # Messages multi-modaux
                # Pour les messages multi-modaux, nous conservons la structure mais nettoyons le texte
                multimodal_content: List[Dict[str, Any]] = []
                message_tokens = self.token_estimator(role) + 4
                
                for item in content:
                    if isinstance(item, dict):
                        if item.get('type') == 'text':
                            text = item.get('text', '')
                            cleaned_text = self.clean_message(text)
                            item_tokens = self.token_estimator(cleaned_text)
                            multimodal_content.append({**item, 'text': cleaned_text})
                            message_tokens += item_tokens
                        else:
                            # Pour les images et autres types, nous estimons un coût fixe
                            multimodal_content.append(item)
                            message_tokens += 100  # Estimation arbitraire pour les éléments non textuels
                
                cleaned_messages.append({
                    'role': role, 
                    'content': multimodal_content, 
                    'tokens': message_tokens
                })
                total_tokens += message_tokens
        
        # Si le total des tokens est dans la limite, nous retournons tous les messages
        if total_tokens <= int(self.max_context_length) - int(self.reserved_tokens):
            # Retirer le champ 'tokens' avant de retourner
            return [{k: v for k, v in msg.items() if k != 'tokens'} for msg in cleaned_messages]
        
        # Préserver les messages système et les premiers prompts utilisateur
        preserved_messages = cleaned_messages[:self.preserved_prompts]
        preserved_tokens_int: int = int(sum(int(msg['tokens']) for msg in preserved_messages))
        
        # Comprimer le contexte si activé
        if self.compression_enabled and len(cleaned_messages) > self.preserved_prompts + 5:
            return self._compress_context(cleaned_messages, preserved_tokens_int)
        
        # Calculer les tokens pour les messages récents
        recent_messages = cleaned_messages[-3:]  # 3 messages les plus récents
        recent_tokens_int: int = int(sum(int(msg['tokens']) for msg in recent_messages))
        
        # Calculer les tokens disponibles pour le résumé
        max_context_length_int: int = int(self.max_context_length)
        reserved_tokens_int: int = int(self.reserved_tokens)
        available_tokens_int: int = max_context_length_int - reserved_tokens_int - preserved_tokens_int - recent_tokens_int
        
        # Garder autant de messages récents que possible
        remaining_messages = cleaned_messages[self.preserved_prompts:]
        included_messages: List[Dict[str, Any]] = []
        
        # Parcourir les messages du plus récent au plus ancien
        for msg in reversed(remaining_messages):
            token_count: int = int(msg['tokens'])
            if token_count <= available_tokens_int:
                included_messages.insert(0, msg)
                available_tokens_int -= token_count
            else:
                # Si un message est trop long, essayer de le tronquer
                if available_tokens_int > 200:  # Seulement si on a encore suffisamment d'espace
                    content = msg['content']
                    role = msg['role']
                    
                    if isinstance(content, str):
                        # Tronquer le contenu texte
                        truncated_content = self.text_cleaner.truncate_text(
                            content, 
                            int(available_tokens_int / 1.3)  # Conversion approximative tokens -> caractères
                        )
                        
                        # Vérifier que la troncature a suffisamment réduit la taille
                        truncated_tokens = self.token_estimator(truncated_content) + self.token_estimator(role) + 4
                        
                        if truncated_tokens <= available_tokens_int:
                            truncated_msg: Dict[str, Any] = {
                                'role': role,
                                'content': truncated_content + "\n[Message tronqué pour respecter la limite de contexte]",
                                'tokens': truncated_tokens
                            }
                            included_messages.insert(0, truncated_msg)
                            available_tokens_int -= truncated_tokens
                    
                break  # Sortir de la boucle après avoir traité le premier message trop long
        
        # Combiner les messages préservés et inclus
        final_messages = preserved_messages + included_messages
        
        # Retirer le champ 'tokens' avant de retourner
        return [{k: v for k, v in msg.items() if k != 'tokens'} for msg in final_messages]
    
    def _compress_context(self, messages: List[Dict[str, Any]], preserved_tokens: int) -> List[Dict[str, Any]]:
        """
        Compresse le contexte en résumant les anciens messages.
        
        Args:
            messages: Liste des messages avec leurs tokens
            preserved_tokens: Nombre de tokens déjà utilisés par les messages préservés
            
        Returns:
            Liste des messages compressée
        """
        # Conserver les messages préservés (système, instructions, etc.)
        preserved_messages = messages[:self.preserved_prompts]
        remaining_messages = messages[self.preserved_prompts:]
        
        # Ne rien faire si nous avons peu de messages
        if len(remaining_messages) <= 5:
            return [{k: v for k, v in msg.items() if k != 'tokens'} for msg in messages]
        
        # Diviser les messages restants en plusieurs groupes
        recent_messages = remaining_messages[-3:]  # 3 messages les plus récents
        older_messages = remaining_messages[:-3]  # Messages plus anciens à compresser
        
        # Calculer les tokens pour les messages récents
        recent_tokens_int: int = int(sum(int(msg['tokens']) for msg in recent_messages))
        
        # Calculer les tokens disponibles pour le résumé
        max_context_length_int: int = int(self.max_context_length)
        reserved_tokens_int: int = int(self.reserved_tokens)
        preserved_tokens_int: int = int(preserved_tokens)
        available_tokens_int: int = max_context_length_int - reserved_tokens_int - preserved_tokens_int - recent_tokens_int
        
        # Créer un résumé des conversations anciennes
        summary = {
            'role': 'system',
            'content': f"[Résumé de {len(older_messages)} messages précédents: "
        }
        
        # Extraire les points clés de chaque message
        points = []
        for msg in older_messages:
            if isinstance(msg['content'], str):
                # Prendre la première phrase ou les X premiers caractères comme point clé
                content = msg['content'].strip()
                first_sentence_match = re.match(r'^(.*?[.!?])\s', content)
                
                if first_sentence_match:
                    summary_point = first_sentence_match.group(1)
                else:
                    summary_point = content[:100] + ("..." if len(content) > 100 else "")
                
                points.append(f"{msg['role']}: {summary_point}")
        
        # Ajouter autant de points que possible dans la limite des tokens
        summary_content = summary['content']
        for point in points:
            point_tokens = self.token_estimator(point + "\n")
            if self.token_estimator(summary_content) + point_tokens <= available_tokens_int:
                summary_content += "\n- " + point
            else:
                summary_content += "\n- [et d'autres messages...]"
                break
        
        summary_content += "]"
        summary['content'] = summary_content
        # Convert token estimation to the expected type (string)
        summary['tokens'] = str(int(self.token_estimator(summary_content)))
        
        # Combiner les messages préservés, le résumé et les messages récents
        final_messages = preserved_messages + [summary] + recent_messages
        
        # Retirer le champ 'tokens' avant de retourner
        return [{k: v for k, v in msg.items() if k != 'tokens'} for msg in final_messages]


class MessageBasedContextManager(ContextManagerBase):
    """
    Gestionnaire de contexte basé sur le nombre de messages.
    """
    def __init__(self, 
                 model_info: Dict[str, Union[int, str]], 
                 preserved_prompts: int = 2, 
                 max_messages: int = 50,
                 smart_pruning: bool = False):
        """
        Initialise le gestionnaire de contexte basé sur le nombre de messages.
        
        Args:
            model_info: Informations sur le modèle
            preserved_prompts: Nombre de prompts à préserver
            max_messages: Nombre maximum de messages à conserver
            smart_pruning: Utiliser l'élagage intelligent des messages
        """
        super().__init__(model_info, preserved_prompts)
        self.max_messages = max_messages
        self.smart_pruning = smart_pruning
        self.message_importance: Dict[int, float] = {}  # Stocke l'importance calculée des messages
        
    def manage_sliding_context(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Gère le contexte glissant, en préservant les messages importants et en respectant le nombre maximum.
        
        Args:
            messages: Liste des messages
            
        Returns:
            Liste des messages ajustée
        """
        # Nettoyer les messages
        cleaned_messages = []
        for msg in messages:
            content = msg.get('content', '')
            role = msg.get('role', '')
            
            if isinstance(content, str):
                cleaned_content = self.clean_message(content)
                cleaned_messages.append({'role': role, 'content': cleaned_content})
            else:  # Messages multi-modaux
                cleaned_content = []
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text':
                        text = item.get('text', '')
                        cleaned_text = self.clean_message(text)
                        cleaned_content.append({**item, 'text': cleaned_text})
                    else:
                        cleaned_content.append(item)
                        
                cleaned_messages.append({'role': role, 'content': cleaned_content})
        
        # Si le nombre de messages est dans la limite, nous retournons tous les messages
        if len(cleaned_messages) <= self.max_messages:
            return cleaned_messages
        
        # Préserver les messages système et les premiers prompts utilisateur
        preserved_messages = cleaned_messages[:self.preserved_prompts]
        remaining_messages = cleaned_messages[self.preserved_prompts:]
        
        # Si l'élagage intelligent est activé, sélectionner les messages les plus importants
        if self.smart_pruning:
            return self._smart_prune_messages(preserved_messages, remaining_messages)
        
        # Sinon, conserver simplement les messages les plus récents
        retained_messages = remaining_messages[-(self.max_messages - len(preserved_messages)):]
        
        return preserved_messages + retained_messages
    
    def _smart_prune_messages(self, preserved_messages: List[Dict[str, str]], remaining_messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Élague intelligemment les messages en conservant les plus importants.
        
        Args:
            preserved_messages: Messages à préserver
            remaining_messages: Messages à élaguer
            
        Returns:
            Liste des messages élaguée
        """
        # Calculer combien de messages nous devons conserver
        num_to_retain = self.max_messages - len(preserved_messages)
        
        if num_to_retain >= len(remaining_messages):
            return preserved_messages + remaining_messages
        
        # Toujours conserver les 3 messages les plus récents
        num_recent = min(3, len(remaining_messages))
        recent_messages = remaining_messages[-num_recent:]
        older_messages = remaining_messages[:-num_recent]
        
        # Nombre de messages anciens à conserver
        num_older_to_retain = num_to_retain - num_recent
        
        if num_older_to_retain <= 0:
            return preserved_messages + recent_messages
        
        # Évaluer l'importance de chaque message
        scored_messages = []
        for idx, msg in enumerate(older_messages):
            content = msg.get('content', '')
            role = msg.get('role', '')
            
            # Extraire le texte pour l'évaluation
            if isinstance(content, list):
                text_content = ""
                for item in content:
                    if isinstance(item, dict) and item.get('type') == 'text':
                        text_content += item.get('text', '')
                content = text_content
            
            # Calculer un score d'importance
            importance = self._calculate_message_importance(content, role, idx, len(older_messages))
            scored_messages.append((importance, msg))
        
        # Trier par importance décroissante et prendre les top N
        scored_messages.sort(key=lambda x: x[0], reverse=True)
        selected_older_messages = [msg for _, msg in scored_messages[:num_older_to_retain]]
        
        # Préserver l'ordre chronologique
        selected_message_indices = [older_messages.index(msg) for msg in selected_older_messages]
        selected_message_indices.sort()
        ordered_selected_messages = [older_messages[i] for i in selected_message_indices]
        
        return preserved_messages + ordered_selected_messages + recent_messages
    
    def _calculate_message_importance(self, content: str, role: str, index: int, total_messages: int) -> float:
        """
        Calcule l'importance d'un message.
        
        Args:
            content: Contenu du message
            role: Rôle de l'expéditeur
            index: Position du message
            total_messages: Nombre total de messages
            
        Returns:
            Score d'importance
        """
        # Attribuer des scores de base selon le rôle
        role_scores = {
            'system': 10.0,
            'assistant': 7.0,
            'user': 5.0,
            'function': 3.0,
            'tool': 3.0
        }
        
        base_score = role_scores.get(role.lower(), 1.0)
        
        # Bonus pour les messages plus récents (position relative)
        recency_score = index / total_messages * 3.0
        
        # Bonus pour les messages contenant des informations clés
        content_score = 0.0
        
        if isinstance(content, str):
            # Détection de code
            if '```' in content or re.search(r'<code>\s*[\s\S]*?\s*</code>', content):
                content_score += 5.0
                
            # Détection d'URLs ou de chemins de fichiers
            if re.search(r'https?://\S+|file:/\S+|/\w+/\S+', content):
                content_score += 2.0
                
            # Détection de questions
            if '?' in content:
                content_score += 1.5
                
            # Bonus pour les messages plus longs (mais pas trop)
            length = len(content)
            if 100 <= length <= 1000:
                content_score += 1.0
            elif length > 1000:
                content_score += 0.5
        
        # Combiner les scores
        total_score = base_score + recency_score + content_score
        
        return total_score

    def calculate_message_importance(self, messages: List[Dict[str, Any]]) -> Dict[int, float]:
        """
        Calcule l'importance de chaque message dans une conversation.
        
        Args:
            messages: Liste des messages
            
        Returns:
            Dictionnaire associant l'index du message à son score d'importance
        """
        message_importance: Dict[int, float] = {}
        # ... existing code ...
        
        return message_importance

    def combine_sliding_windows(self, windows: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Combine les fenêtres glissantes en un seul contexte.
        
        Args:
            windows: Liste des fenêtres de messages
            
        Returns:
            Liste combinée des messages
        """
        combined_context: List[Dict[str, Any]] = []
        # ... existing code ...
        
        return combined_context


class ContextWindowManager:
    """
    Gestionnaire de fenêtre de contexte avancé avec prise en charge de fenêtres multiples.
    """
    def __init__(self, 
                 model_info: Dict[str, Union[int, str]], 
                 window_size: int = 10, 
                 max_windows: int = 5,
                 overlap: int = 2):
        """
        Initialise le gestionnaire de fenêtres de contexte.
        
        Args:
            model_info: Informations sur le modèle (context_window, etc.)
            window_size: Taille de chaque fenêtre
            max_windows: Nombre maximum de fenêtres à conserver
            overlap: Nombre de messages de chevauchement entre les fenêtres
        """
        self.model_info = model_info
        self.window_size = window_size
        self.max_windows = max_windows
        self.overlap = overlap
        
        self.windows: List[List[Dict[str, Any]]] = []
        self.history_buffer: List[Dict[str, Any]] = []
        self.message_index: Dict[int, Dict[str, Any]] = {}
        self.next_id = 0
        self.text_cleaner = TextCleaner()
        
    def add_message(self, message: Dict[str, str]) -> None:
        """
        Ajoute un message au gestionnaire de contexte.
        
        Args:
            message: Message à ajouter
        """
        # Nettoyer le message
        content = message.get('content', '')
        role = message.get('role', '')
        
        if isinstance(content, str):
            cleaned_content = self.text_cleaner.clean_text(content)
            cleaned_message = {'role': role, 'content': cleaned_content}
        else:  # Messages multi-modaux
            cleaned_content = []
            for item in content:
                if isinstance(item, dict) and item.get('type') == 'text':
                    text = item.get('text', '')
                    cleaned_text = self.text_cleaner.clean_text(text)
                    cleaned_content.append({**item, 'text': cleaned_text})
                else:
                    cleaned_content.append(item)
                    
            cleaned_message = {'role': role, 'content': cleaned_content}
            
        # Ajouter au buffer d'historique
        self.history_buffer.append(cleaned_message)
        
        # Mettre à jour les fenêtres
        self._update_windows()
        
    def get_current_context(self, max_messages: Optional[int] = None) -> List[Dict[str, str]]:
        """
        Retourne le contexte actuel.
        
        Args:
            max_messages: Nombre maximum de messages à inclure
            
        Returns:
            Liste des messages du contexte
        """
        # Si aucune fenêtre n'existe, retourner le buffer d'historique
        if not self.windows:
            context = list(self.history_buffer)
            if max_messages:
                return context[-max_messages:]
            return context
        
        # Combiner toutes les fenêtres
        combined_context: List[Dict[str, Any]] = []
        seen_messages = set()  # Pour éviter les doublons
        
        # Parcourir les fenêtres de la plus récente à la plus ancienne
        for window in reversed(self.windows):
            for msg in reversed(window):
                # Créer une empreinte unique pour le message
                msg_content = msg.get('content', '')
                if isinstance(msg_content, list):
                    # Pour les messages multi-modaux, extraire le texte
                    text_content = ""
                    for item in msg_content:
                        if isinstance(item, dict) and item.get('type') == 'text':
                            text_content += item.get('text', '')
                    msg_content = text_content
                
                # Créer une empreinte unique pour le message
                msg_fingerprint = f"{msg.get('role', '')}:{msg_content[:50]}"
                
                if msg_fingerprint not in seen_messages:
                    combined_context.insert(0, msg)
                    seen_messages.add(msg_fingerprint)
        
        # Appliquer la limite de messages
        if max_messages and len(combined_context) > max_messages:
            return combined_context[-max_messages:]
            
        return combined_context
    
    def _update_windows(self) -> None:
        """
        Met à jour les fenêtres de contexte.
        """
        # S'il n'y a pas assez de messages pour former une fenêtre complète
        if len(self.history_buffer) < self.window_size:
            self.windows = [list(self.history_buffer)]
            return
        
        # Créer une nouvelle fenêtre avec les messages les plus récents
        new_window = list(self.history_buffer)[-self.window_size:]
        
        # Si c'est la première fenêtre
        if not self.windows:
            self.windows.append(new_window)
            return
        
        # Vérifier le chevauchement avec la fenêtre la plus récente
        last_window = self.windows[-1]
        overlap_detected = False
        
        # Vérifier si la nouvelle fenêtre chevauche suffisamment la dernière fenêtre
        for i in range(1, min(self.overlap + 1, len(last_window), len(new_window))):
            if last_window[-i:] == new_window[:i]:
                overlap_detected = True
                break
        
        # Si pas de chevauchement, ajouter une nouvelle fenêtre
        if not overlap_detected:
            self.windows.append(new_window)
            
            # Limiter le nombre de fenêtres
            if len(self.windows) > self.max_windows:
                self.windows.pop(0)
        else:
            # Mettre à jour la dernière fenêtre
            self.windows[-1] = new_window

    def calculate_message_importance(self, messages: List[Dict[str, Any]]) -> Dict[int, float]:
        """
        Calcule l'importance de chaque message dans une conversation.
        
        Args:
            messages: Liste des messages
            
        Returns:
            Dictionnaire associant l'index du message à son score d'importance
        """
        message_importance: Dict[int, float] = {}
        # ... existing code ...
        
        return message_importance

    def combine_sliding_windows(self, windows: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        """
        Combine les fenêtres glissantes en un seul contexte.
        
        Args:
            windows: Liste des fenêtres de messages
            
        Returns:
            Liste combinée des messages
        """
        combined_context: List[Dict[str, Any]] = []
        # ... existing code ...
        
        return combined_context
