#!/usr/bin/bash
# helios-watch-auth.sh - bloque les sources d'échecs d'authentification SSH répétés.
# Fenêtre glissante de 10 min ; au-delà de 5 échecs, l'adresse est ajoutée à l'ipset helios-blacklist.
# Sortie : 0 OK · 1 erreur interne · 2 verrou déjà pris · 3 prérequis manquant
set -euo pipefail
IFS=$'\n\t'
readonly TAG=helios-watch-auth
readonly LOCK=/run/lock/helios-watch-auth.lock
readonly IPSET=helios-blacklist
readonly WINDOW='-10min'
readonly THRESHOLD=5
readonly STATE=/var/lib/helios/blocked.txt
readonly WHITELIST=(192.168.56.1 127.0.0.1)   # 192.168.56.1 : poste du formateur (hôte VirtualBox)

log() { logger -t "$TAG" -p "authpriv.${1}" -- "$2" ; }
die() { log err "$1" ; exit "${2:-1}" ; }
trap 'rc=$? ; log info "fin d execution rc=${rc}"' EXIT
trap 'die "interrompu par signal" 1' INT TERM

exec 9>"$LOCK"
flock -n 9 || { log warning "une autre instance tourne deja" ; exit 2 ; }

command -v firewall-cmd >/dev/null || die "firewall-cmd absent" 3
firewall-cmd --state >/dev/null 2>&1 || die "firewalld inactif" 3
firewall-cmd --get-ipsets | grep -qw "$IPSET" || die "ipset $IPSET absent" 3
touch "$STATE"

# Adresse source de chaque échec : utilisateur inconnu, clé ou mot de passe refusés
counts=$(journalctl -u sshd --since "$WINDOW" -o cat --no-pager \
         | grep -oP '(Invalid user \S+ from |Failed \S+ for (invalid user )?\S+ from )\K[0-9.]+' \
         | sort | uniq -c || true)

nb=0
while IFS=' ' read -r n ip ; do
    [[ -n "${ip:-}" ]] || continue
    (( n > THRESHOLD )) || continue
    for w in "${WHITELIST[@]}" ; do
        if [[ "$ip" == "$w" ]] ; then log notice "liste blanche : ${ip} (${n} echecs) non bloque" ; continue 2 ; fi
    done
    # idempotence : une adresse déjà bloquée ne génère pas de nouvelle alerte
    if grep -qxF "$ip" "$STATE" || firewall-cmd --ipset="$IPSET" --query-entry="$ip" >/dev/null 2>&1 ; then continue ; fi
    firewall-cmd --ipset="$IPSET" --add-entry="$ip" >/dev/null
    firewall-cmd --permanent --ipset="$IPSET" --add-entry="$ip" >/dev/null
    echo "$ip" >> "$STATE"
    log warning "blocage de ${ip} : ${n} echecs SSH en 10 min"
    nb=$((nb + 1))
done <<< "$counts"
log info "analyse terminee : ${nb} nouvelle(s) adresse(s) bloquee(s)"
exit 0
