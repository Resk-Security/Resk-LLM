"""
Liste des mots et expressions prohibés pour la détection d'attaques potentielles contre les agents LLM.

Ce module fournit une liste complète de termes liés à la sécurité informatique, aux attaques 
et aux tentatives de manipulation qui pourraient être utilisés dans des messages malveillants 
ciblant les agents LLM. Ces mots-clés sont utilisés par le module ReskWordsLists pour 
détecter les tentatives d'attaques.
"""

# Liste principale des mots prohibés
RESK_WORDS_LIST = {
    # Termes généraux d'attaque
    "jailbreak", "bypass", "hack", "exploit", "override",
    "injection", "malware", "rootkit", "backdoor", "trojan",
    "phishing", "spyware", "keylogger", "ransomware", "botnet",
    "ddos", "xss", "sql injection", "buffer overflow", "zero-day",
    "brute force", "man-in-the-middle", "privilege escalation",
    
    # Techniques de manipulation
    "social engineering", "data breach", "identity theft",
    "cryptojacking", "malicious code", "exploit kit", "rat",
    "rootkit", "worm", "spear phishing", "vishing", "smishing",
    "doxing", "cyberstalking", "cyberextortion", "cyberterrorism",
    
    # Menaces avancées
    "advanced persistent threat", "apt", "watering hole attack",
    "evil twin", "rogue access point", "eavesdropping", "spoofing",
    "sniffing", "packet injection", "session hijacking", "backdoor",
    
    # Logiciels et codes malveillants
    "logic bomb", "trojan horse", "virus", "polymorphic virus",
    "metamorphic virus", "macro virus", "boot sector virus",
    "file infector virus", "multipartite virus", "stealth virus",
    "armored virus", "cavity virus", "sparse infector virus",
    "companion virus", "fab virus", "overwrite virus", "parasitic virus",
    "resident virus", "non-resident virus", "tunneling virus",
    "multipartite virus", "cluster virus", "shell virus", "file virus",
    "macro virus", "polymorphic virus", "metamorphic virus",
    "encrypted virus", "stealth virus", "cavity virus", "sparse infector",
    "companion virus", "file overwriting virus", "file adding virus",
    "boot sector virus", "master boot record virus", "rootkit",
    
    # Types spécifiques de rootkits
    "kernel rootkit", "user-mode rootkit", "firmware rootkit",
    "virtual rootkit", "bootkit", "hypervisor-level rootkit"
} 