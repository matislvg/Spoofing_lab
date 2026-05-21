#!/usr/bin/env python3
"""
===============================================================================
 Labo Spoofing & Analyse de Trafic — Scapy (Version Certifiée)
 Missions :
   1. Envoyer des paquets ICMP malformés avec IP source spoofée
   2. Inonder le réseau local de fausses requêtes ARP (Mac & IP uniques)
   3. Capturer, analyser et exporter le trafic au format PCAP (Multi-threading)
===============================================================================
 ⚠️ Usage strictement pédagogique sur réseau isolé. Permissions Admin requises.
"""

import os
import sys
import time
import argparse
import threading
from scapy.all import (
    IP, ICMP, Ether, ARP,
    send, sendp, sniff,
    conf, RandMAC, wrpcap, get_if_list
)

# ─────────────────────────────────────────────────────────────────────────────
#  VÉRIFICATION DES PRIVILÈGES
# ─────────────────────────────────────────────────────────────────────────────
def check_privileges():
    """Vérifie si le script est exécuté avec les droits admin sans masquer les erreurs."""
    if os.name == 'nt':  # Windows
        import ctypes
        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    else:  # Linux / macOS
        is_admin = os.geteuid() == 0

    if not is_admin:
        print("[-] ERREUR : Ce script nécessite des privilèges d'administrateur.")
        print("    -> Linux/macOS : sudo python3 spoofing_lab.py")
        print("    -> Windows     : Exécuter le terminal en tant qu'Administrateur")
        sys.exit(1)

# ─────────────────────────────────────────────────────────────────────────────
#  PARTIE 1 — ICMP Malformé (IP source spoofée)
# ─────────────────────────────────────────────────────────────────────────────
def send_spoofed_icmp(target_ip: str, spoof_ip: str, count: int, payload: bytes, verbose: bool):
    """Envoie des paquets ICMP Echo Request avec une IP source falsifiée."""
    print(f"\n[ICMP SPOOF] Envoi de {count} paquets vers {target_ip} (Source: {spoof_ip})")
    
    paquet = (
        IP(src=spoof_ip, dst=target_ip, ttl=1) 
        / ICMP(type=8, code=0, id=0xDEAD) 
        / payload
    )

    if verbose:
        print("\n--- Structure du paquet ICMP injecté ---")
        paquet.show()
        print("----------------------------------------\n")

    for i in range(count):
        send(paquet, verbose=False)
        if verbose:
            print(f"  [+] Paquet ICMP {i+1}/{count} envoyé")
        time.sleep(0.3)

# ─────────────────────────────────────────────────────────────────────────────
#  PARTIE 2 — ARP Flooding (Fausses requêtes ARP)
# ─────────────────────────────────────────────────────────────────────────────
def arp_flood(target_ip: str, iface: str, count: int, verbose: bool):
    """Inonde le réseau de requêtes ARP avec des IPs et MACs cohérentes et aléatoires."""
    print(f"[ARP FLOOD] Envoi de {count} fausses requêtes ARP sur l'interface : {iface}")

    for i in range(count):
        fake_src_ip = f"10.0.{i // 256}.{i % 256}" 
        # Forçage en string pour garantir la stricte égalité entre couche 2 et couche 3 (Point 2)
        random_mac = str(RandMAC())

        paquet = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=random_mac)
            / ARP(
                op=1,  # ARP Request (who-has)
                pdst=target_ip,
                psrc=fake_src_ip,
                hwsrc=random_mac
            )
        )

        sendp(paquet, iface=iface, verbose=False)
        if verbose:
            print(f"  [+] ARP Request {i+1:>3}/{count} — src: {fake_src_ip} via MAC: {random_mac}")
        time.sleep(0.02)

# ─────────────────────────────────────────────────────────────────────────────
#  PARTIE 3 — Capture, Analyse et Exportation
# ─────────────────────────────────────────────────────────────────────────────
def generate_callback(verbose: bool):
    """Génère le callback d'analyse en fonction du niveau de verbosité (Closure)."""
    def analyse_paquet(pkt):
        if not verbose:
            return
        if pkt.haslayer(ICMP):
            ip = pkt[IP]
            print(f"  [CAPTURED ICMP] src={ip.src:<15} dst={ip.dst:<15} ttl={ip.ttl}")
        elif pkt.haslayer(ARP):
            arp = pkt[ARP]
            op = "Request" if arp.op == 1 else "Reply"
            print(f"  [CAPTURED ARP]  src_ip={arp.psrc:<15} dst_ip={arp.pdst:<15} op={op}")
    return analyse_paquet

def capture_traffic(iface: str, duration: int, spoof_ip: str, payload_signature: bytes, output_pcap: str, sniffer_ready_event: threading.Event, verbose: bool):
    """Capture le trafic réseau, applique l'analyse et exporte en PCAP."""
    if verbose:
        print(f"[CAPTURE] Initialisation de l'écoute sur {iface} (Filtre: ICMP ou ARP)...")
    
    captured_packets = []

    def on_sniff_start():
        """Déclenché dès que Scapy écoute activement sur l'interface (Libère le wait)."""
        sniffer_ready_event.set()

    try:
        paquets = sniff(
            iface=iface,
            filter="icmp or arp",
            prn=generate_callback(verbose),
            timeout=duration,
            started_callback=on_sniff_start,
            store=True
        )
        if paquets:
            captured_packets.extend(paquets)
    except Exception as e:
        print(f"\n[-] ERREUR CRITIQUE dans le thread de capture : {e}")
        sniffer_ready_event.set()  # Libère le wait() immédiatement au lieu d'attendre le timeout
        return

    print(f"\n=== RAPPORT DE CAPTURE ===")
    print(f"[•] Total paquets interceptés : {len(captured_packets)}")
    
    icmp_pkts = [p for p in captured_packets if p.haslayer(ICMP)]
    arp_pkts = [p for p in captured_packets if p.haslayer(ARP)]
    print(f"    -> Paquets ICMP : {len(icmp_pkts)}")
    print(f"    -> Paquets ARP  : {len(arp_pkts)}")

    # Détection robuste par analyse de la charge brute (Point 5)
    spoofed = [
        p for p in icmp_pkts 
        if p.haslayer(IP) and p[IP].src == spoof_ip and payload_signature in bytes(p)
    ]
    
    if spoofed:
        print(f"\n[✓] ALERTE DÉTECTION : Attaque par spoofing identifiée !")
        print(f"    -> Critère 1 : Correspondance IP source ({spoof_ip})")
        print(f"    -> Critère 2 : Signature de payload détectée dans la trame raw.")
    else:
        print(f"\n[!] RECONNAISSANCE : Aucune attaque par signature validée.")

    # Exportation PCAP
    if output_pcap and len(captured_packets) > 0:
        wrpcap(output_pcap, captured_packets)
        print(f"[✓] Trafic exporté avec succès dans : {output_pcap}")
    print("==========================\n")

# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    check_privileges()

    parser = argparse.ArgumentParser(
        description="Labo Cyber — Spoofing & Sniffing Réseau Évolué",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--mode", choices=["send", "capture", "all"], default="all", help="Mode d'exécution")
    parser.add_argument("--target", type=str, default="192.168.56.101", help="IP de la VM cible")
    parser.add_argument("--spoof-ip", type=str, default="10.0.0.99", help="IP usurpée pour l'attaque ICMP")
    parser.add_argument("--iface", type=str, default=None, help="Interface réseau (Optionnel)")
    parser.add_argument("--count", type=int, default=10, help="Nombre de paquets de base")
    parser.add_argument("--duration", type=int, default=15, help="Durée de la capture (secondes)")
    parser.add_argument("--pcap", type=str, default="capture_labo.pcap", help="Fichier d'export PCAP")
    parser.add_argument("--verbose", action="store_true", help="Affiche le flux détaillé des paquets en temps réel")

    args = parser.parse_args()

    # Résolution et affichage informatif des interfaces (Ce qui manque)
    interfaces_disponibles = get_if_list()
    interface_active = args.iface if args.iface else conf.iface

    print("\n" + "="*60)
    print("  LABO CYBERSÉCURITÉ V3 — SCAPY PRODUCTION READY")
    print(f"  Interface unique retenue   : {interface_active}")
    print(f"  Interfaces dispo détectées : {interfaces_disponibles[:3]}... ({len(interfaces_disponibles)} au total)")
    print("="*60 + "\n")

    PAYLOAD_SIGNATURE = b"SPOOFED_ICMP_PAYLOAD_LABO"
    sniffer_ready = threading.Event()

    try:
        if args.mode == "capture":
            capture_traffic(interface_active, args.duration, args.spoof_ip, PAYLOAD_SIGNATURE, args.pcap, sniffer_ready, verbose=True)

        elif args.mode == "send":
            send_spoofed_icmp(args.target, args.spoof_ip, args.count, PAYLOAD_SIGNATURE, verbose=True)
            arp_flood(args.target, interface_active, args.count * 2, verbose=True)

        elif args.mode == "all":
            thread_capture = threading.Thread(
                target=capture_traffic, 
                args=(interface_active, args.duration, args.spoof_ip, PAYLOAD_SIGNATURE, args.pcap, sniffer_ready, args.verbose),
                daemon=True
            )
            thread_capture.start()

            # Anti-blocage infini : Timeout de 10s (Point 3)
            if not args.verbose:
                print("[*] Attente de l'activation du sniffer réseau...")
            
            is_ready = sniffer_ready.wait(timeout=10.0)

            # Vérification de la viabilité du thread daemon (Point 4)
            if not is_ready or not thread_capture.is_alive():
                print("[-] ERREUR : Le sniffer n'a pas pu démarrer à temps ou a crashé.")
                print("    -> Vérifiez la validité de votre interface réseau ou vos droits sudo.")
                sys.exit(1)

            # Injection si et seulement si le sniffer écoute activement
            send_spoofed_icmp(args.target, args.spoof_ip, args.count, PAYLOAD_SIGNATURE, args.verbose)
            arp_flood(args.target, interface_active, args.count * 2, args.verbose)

            if not args.verbose:
                print("[*] Attente de la fin de la capture des paquets résiduels...")
            thread_capture.join()

    except KeyboardInterrupt:
        print("\n[!] Script interrompu par l'utilisateur (Ctrl+C). Fermeture propre.")
        sys.exit(0)

    print("[FIN] Labo terminé avec succès.")

if __name__ == "__main__":
    main()