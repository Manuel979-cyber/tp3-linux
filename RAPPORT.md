# TP3 — Pare-feu, durcissement SSH et journaux

**Auteur** : Beka Kamewe Manuel — **Date** : 04/11/2026 — **Environnement** : Rocky Linux 9.8, srv-core (cible) et srv-edge (poste distant)

## 1. Tableau interface → zone → politique

| Interface | Réseau | Zone | Politique | Justification |
|---|---|---|---|---|
| `enp0s3` | NAT (sortie Internet) | **drop** | Rien n'entre, aucune réponse | Carte utilisée seulement pour sortir. Personne ne doit pouvoir s'y connecter |
| `enp0s8` (connexion `admin`) | 192.168.56.0/24, administration | **work** | Seulement SSH (2242), journalisé `SSH-NEW` et limité à 6 connexions/min ; 10051 rejeté ; blacklist jetée | Seule porte d'entrée des administrateurs, protégée contre la force brute |
| `bond0`, `bond0.42` | réseau interne `helios-lan` et VLAN 42 | **internal** | SSH (2242) et 10051/tcp (supervision) | Réseau de confiance entre serveurs, le flux métier 10051 y est autorisé |
| Zone par défaut | — | **drop** | Rien n'entre | Une nouvelle interface sans zone est fermée par défaut |

## 2. Interaction crypto-policies / sshd_config

Sur Rocky 9, sshd prend ses algorithmes dans la politique cryptographique du système. Le fichier `/etc/ssh/sshd_config.d/50-redhat.conf` inclut `/etc/crypto-policies/back-ends/opensshserver.config`.

sshd garde la **première** valeur lue. Une ligne `Ciphers`, `KexAlgorithms` ou `MACs` placée après `50-redhat.conf` est donc **ignorée sans erreur**. Pour qu'elle compte, il faut la mettre dans un fichier lu avant, d'où le nom `05-helios-crypto.conf`. Elle ne peut pas non plus être dans un bloc `Match`.

Résultat mesuré avec `sshd -T` :
- avec seulement `update-crypto-policies --set DEFAULT:NO-SHA1`, les MAC `hmac-sha1` restent proposés ;
- avec `05-helios-crypto.conf` en plus, il ne reste que `curve25519` / `dh-group16-sha512`, `chacha20-poly1305` / `aes256-gcm` / `aes256-ctr` et des MAC SHA-2 en mode etm.

La méthode recommandée sur RHEL 9 reste la politique système, qui s'applique aussi aux autres logiciels (OpenSSL, etc.).

## 3. Cinq requêtes d'investigation

| Requête | Ce qu'elle révèle |
|---|---|
| `journalctl -u sshd.service --since '-2h' -p warning` | L'échec de démarrage de sshd à 14:27:28 : `Bind to port 2242 … Permission denied` (SELinux) |
| `journalctl _SYSTEMD_UNIT=sshd.service -g 'Invalid user\|Failed\|Accepted'` | Toutes les connexions réussies, avec l'empreinte de la clé utilisée. Les connexions viennent seulement de mon poste (.1) et de srv-edge (.11) |
| `journalctl -t sudo --since today -o json-pretty` | `_AUDIT_LOGINUID=5104` : on sait que c'est sysops qui a lancé la commande root, même après `sudo` |
| `journalctl -b -1 -p err` | Les erreurs du démarrage précédent (pilote e1000, échec sshd). Possible seulement grâce au journal persistant |
| `lastb` / `last -F` | Les échecs de connexion de nadia au TP2 (test faillock) et des sessions marquées `crash` (arrêts brutaux de VirtualBox) |

## 4. Les trois conséquences d'un changement de port SSH sur RHEL 9

1. **SELinux** : sshd n'a le droit d'écouter que sur les ports de type `ssh_port_t` (22 par défaut). Il faut `semanage port -a -t ssh_port_t -p tcp 2242`, sinon sshd ne démarre pas. Je l'ai vu en vrai : `avc: denied { name_bind } … src=2242`.
2. **Pare-feu** : le service firewalld `ssh` correspond au port 22. Il faut ouvrir 2242 et retirer le service `ssh`, dans chaque zone (`work` et `internal`).
3. **Clients et outils** : tout ce qui se connecte doit utiliser le nouveau port (`ssh -p 2242`, `scp -P 2242`, `~/.ssh/config`, scripts, supervision, sauvegardes).

Changer le port ne protège pas en soi, ça réduit juste le bruit des robots. La vraie protection vient de la clé obligatoire, de `AllowGroups` et du pare-feu.

## 5. Vérifications (`verifications/`, commandes tapées sur les consoles de srv-core et srv-edge)

| Capture | Ce qui est vérifié |
|---|---|
| `01-zones.png` | zone par défaut `drop`, interfaces dans leur zone |
| `02-regles-riches.png` | règles riches de `work` (SSH-NEW, limite, 10051, blacklist) |
| `03-sshd.png` | `sshd -T` : port 2242, root interdit, clé obligatoire, `ssh-admins` |
| `04-selinux-port.png` | `ssh_port_t` contient 2242, sshd écoute sur 2242, politique crypto |
| `05-ssh-new.png` | lignes `SSH-NEW` dans le journal noyau |
| `06-journald.png` | journald persistant et scellé, plusieurs démarrages |
| `07-auditd.png` | règles auditd chargées, événements `sudoers` |
| `08-watch-auth.png` | timer de détection actif (prochaine exécution dans la minute) |
| `09-ipset.png` | ipset `helios-blacklist` (vide depuis le déblocage) |
| `10-edge-tests-ssh.png` | depuis srv-edge : port 22 fermé, sysops accepté, root et nadia refusés |
| `11-edge-kex-sha1.png` | depuis srv-edge : échange de clés SHA-1 refusé |
