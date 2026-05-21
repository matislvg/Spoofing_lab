# 🛡️ Scapy Spoofing & Sniffing Lab

Un outil "tout-en-un" en Python utilisant la bibliothèque **Scapy** pour simuler des attaques de niveau couche 2 (ARP) et couche 3 (ICMP), tout en capturant le trafic en temps réel pour analyser et détecter les menaces.

Ce projet a été développé dans un but purement pédagogique pour illustrer la fragilité des protocoles réseau de base et comprendre les mécanismes de détection par signature.

## ✨ Fonctionnalités

* **Multi-threading synchronisé :** Utilise `threading.Event` pour s'assurer que le module de capture (Sniffer) est pleinement actif avant de déclencher les injections de paquets.
* **Spoofing ICMP (Couche 3) :** Génération de paquets *Echo Request* (Ping) malformés avec usurpation de l'IP source (`10.0.0.99`) et un TTL anormalement bas (`TTL=1`).
* **ARP Flooding (Couche 2) :** Inondation de requêtes ARP (*who-has*) en modifiant dynamiquement l'IP fantôme et en forçant des adresses MAC aléatoires (`RandMAC()`) cohérentes entre les couches Ethernet et ARP.
* **Analyse & Détection automatique :** Inspection en mémoire des trames brutes à la recherche d'une signature numérique spécifique (`SPOOFED_ICMP_PAYLOAD_LABO`).
* **Export Forensique PCAP :** Sauvegarde automatique des paquets interceptés dans un fichier `.pcap` compatible avec Wireshark.

## 🚀 Installation & Prérequis

### Prérequis
Le script nécessite des privilèges d'administration (Root sur Linux, Administrateur sur Windows) pour forger et injecter des trames de couches 2 et 3.
> **Windows uniquement :** Installez [Npcap](https://npcap.com) avant de lancer le script. Sans ce driver, Scapy ne peut pas forger de paquets.

### Dépendances
Installez la bibliothèque Scapy :
```bash
pip install scapy

```

## 💻 Utilisation

Le script propose trois modes d'exécution via des arguments en ligne de commande :

### 1. Mode Complet automatisé (Recommandé)

Lance la capture en tâche de fond, attend sa liaison à l'interface, puis injecte les attaques.

```bash
# Exemple sur Windows (Invite de commandes Admin)
python spoofing_lab.py --mode all --target 192.168.56.102 --count 20 --duration 30 --verbose

# Exemple sur Linux
sudo python3 spoofing_lab.py --mode all --target 192.168.56.102 --count 20 --duration 30 --verbose

```

### 2. Mode Attaque Seule

```bash
sudo python3 spoofing_lab.py --mode send --target 192.168.56.102

```

### 3. Mode Capture Seule

```bash
sudo python3 spoofing_lab.py --mode capture --duration 20

```

## ⚙️ Arguments

| Argument | Défaut | Description |
|---|---|---|
| `--mode` | `all` | Mode d'exécution : `send`, `capture`, `all` |
| `--target` | `192.168.56.101` | IP de la machine cible |
| `--spoof-ip` | `10.0.0.99` | IP source falsifiée pour l'ICMP |
| `--iface` | Auto | Interface réseau |
| `--count` | `10` | Nombre de paquets à envoyer |
| `--duration` | `15` | Durée de la capture (secondes) |
| `--pcap` | `capture_labo.pcap` | Fichier d'export PCAP |
| `--verbose` | `False` | Affichage détaillé en temps réel |

## 📊 Preuve de Concept & Analyse Wireshark

L'outil génère un rapport de capture directement dans le terminal et exporte un fichier `capture_labo.pcap`.

Voici un aperçu visuel du trafic généré par le script et intercepté dans Wireshark :

<img width="1916" height="1032" alt="Capture d&#39;écran 2026-05-21 094915" src="https://github.com/user-attachments/assets/e6e2c5d3-e76f-42d7-88b2-8321ea78a5a5" />

* **Zone Rose :** Paquets ICMP falsifiés provenant de la source `10.0.0.99` avec un identifiant marqué `0xdead`.
* **Zone Jaune :** Storm de requêtes ARP générant des adresses MAC et des adresses sources séquentielles (`10.0.0.x`).



## ⚠️ Avertissement Légal (Disclaimer)

Cet outil est fourni uniquement à des fins éducatives et de recherche en isolation (environnement de laboratoire, machines virtuelles host-only). L'auteur décline toute responsabilité en cas d'usage malveillant ou hors d'un cadre autorisé.
