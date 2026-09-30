#!/bin/bash
# europa-mail-audit.sh
#
# Eind-tot-eind onderzoek: welke mailproviders gebruiken subdomeinen onder
# een gegeven domein (standaard europa.eu), en waar zit de eigenaar van
# die provider (EU / Microsoft / overige VS / overig / onbekend).
#
# Vereist: subfinder, dnsx, curl, jq, dig (van dnsutils/bind9-dnsutils)
#
# Gebruik: ./europa-mail-audit.sh [domein] [werkdir]
#   domein   - standaard: europa.eu
#   werkdir  - standaard: ~/<domein>

set -uo pipefail

DOMAIN="${1:-europa.eu}"
WORKDIR="${2:-$HOME/${DOMAIN}}"
PARALLEL_DNS=50
PARALLEL_GEO=8

mkdir -p "$WORKDIR"
cd "$WORKDIR" || exit 1

log() { echo "[$(date '+%H:%M:%S')] $*" >&2; }

# ---------------------------------------------------------------------------
# Curated eigenaarschap-tabel: domeinsuffix -> regio -> naam
# Regio's: EU, US, OTHER
# Dit is handwerk/kennis, geen automatische lookup (die bestaat niet voor
# "wie is de eigenaar"). Vul aan als het UNKNOWN-overzicht aan het eind
# nog hostnamen toont.
# ---------------------------------------------------------------------------
write_owner_map() {
  cat > owner-map.tsv << 'MAP_EOF'
mail.ovh.net	EU	OVH (Frankrijk)
stagingsite.ovh	EU	OVH (Frankrijk)
rixx.de	EU	Duits domein
managed-otrs.com	EU	OTRS AG (Duitsland)
tremend.com	EU	Tremend Software Consulting (Roemenie)
eib.org	EU	Europese Investeringsbank (Luxemburg)
odoo.com	EU	Odoo SA (Belgie)
mailgun.org	EU	Mailgun / Sinch (Zweden)
mailprotect.be	EU	Belgische partij
t-systems.com	EU	T-Systems / Deutsche Telekom (Duitsland)
flowmailer.net	EU	Flowmailer (Nederland)
man.poznan.pl	EU	PSNC onderzoeksnetwerk (Polen)
hornetsecurity.com	EU	Hornetsecurity (Duitsland)
crsend.com	EU	CleverReach (Duitsland)
messagelabs.com	US	Broadcom / Symantec (VS)
amazonses.com	US	Amazon (VS)
amazonaws.com	US	Amazon (VS)
appian-customer.com	US	Appian Corporation (VS)
zendesk.com	US	Zendesk (VS)
gitlabhost.io	US	GitLab (VS)
ppe-hosted.com	US	Proofpoint (VS)
iphmx.com	US	Cisco IronPort (VS)
sendgrid.net	US	Twilio SendGrid (VS)
exacttarget.com	US	Salesforce Marketing Cloud (VS)
avature.net	US	Avature (VS, NY-hoofdkantoor)
smtp2go.net	OTHER	SMTP2GO (Australie)
protonmail.ch	OTHER	Proton AG (Zwitserland)
andeo-hosting.ch	OTHER	Zwitserse partij
zoho.eu	OTHER	Zoho Corporation (moederbedrijf India)
MAP_EOF
}

# ---------------------------------------------------------------------------
# Stap 1: subdomeinen verzamelen (crt.sh + subfinder) en resolven (dnsx)
# ---------------------------------------------------------------------------
step1_collect() {
  log "Stap 1/5: subdomeinen verzamelen voor $DOMAIN ..."

  for i in 1 2 3 4 5; do
    curl -s --max-time 300 "https://crt.sh/?q=%25.${DOMAIN}&output=json" -o crt.json
    jq empty crt.json 2>/dev/null && break
    log "  crt.sh timeout/fout, retry $i/5 ..."
    sleep 20
  done
  jq -r '.[].name_value' crt.json 2>/dev/null | tr 'A-Z' 'a-z' | sed 's/^\*\.//' | tr -d '\r' \
    | grep -E "(^|\.)$(echo "$DOMAIN" | sed 's/\./\\./g')\$" | sort -u > crt.txt
  log "  crt.sh: $(wc -l < crt.txt) hostnamen"

  subfinder -d "$DOMAIN" -all -silent -o subfinder.txt 2>/dev/null
  log "  subfinder: $(wc -l < subfinder.txt) hostnamen"

  cat crt.txt subfinder.txt 2>/dev/null | grep -E "(^|\.)$(echo "$DOMAIN" | sed 's/\./\\./g')\$" | sort -u > all-candidates.txt
  log "  totaal kandidaten (uniek): $(wc -l < all-candidates.txt)"

  log "  DNS-resolutie van kandidaten (dnsx, parallel $PARALLEL_DNS) ..."
  dnsx -l all-candidates.txt -silent -a -cname -resp -retry 2 -rl 100 -o resolved.txt 2>/dev/null
  awk '{print $1}' resolved.txt | sort -u > subdomains-live.txt
  log "  live subdomeinen: $(wc -l < subdomains-live.txt)"
}

# ---------------------------------------------------------------------------
# Stap 2: MX-lookup en classificatie (microsoft/google/proofpoint/mimecast/other/hostname_only)
# ---------------------------------------------------------------------------
step2_mxcheck() {
  local input="subdomains-live.txt"
  local total
  total=$(wc -l < "$input")
  log "Stap 2/5: MX-lookup voor $total hostnamen ..."

  check_one() {
    local host="$1"
    local mx
    mx=$(dig +time=3 +tries=1 +short MX "$host" 2>/dev/null | awk 'NF{$NF=$NF; print}' | sort)

    if [[ -z "$mx" ]]; then
      echo -e "${host}\t-\thostname_only"
      return
    fi

    local mxlist
    mxlist=$(echo "$mx" | awk '{print $2}' | paste -sd, -)
    local lc
    lc=$(echo "$mx" | tr 'A-Z' 'a-z')

    local provider="other"
    if echo "$lc" | grep -qE 'outlook\.com\.?$|protection\.outlook\.com\.?$|mail\.protection\.outlook\.com\.?$'; then
      provider="microsoft"
    elif echo "$lc" | grep -qE 'google\.com\.?$|googlemail\.com\.?$|aspmx.*google'; then
      provider="google"
    elif echo "$lc" | grep -qE 'proofpoint\.com\.?$|pphosted\.com\.?$'; then
      provider="proofpoint"
    elif echo "$lc" | grep -qE 'mimecast\.com\.?$'; then
      provider="mimecast"
    fi
    echo -e "${host}\t${mxlist}\t${provider}"
  }
  export -f check_one

  xargs -a "$input" -P "$PARALLEL_DNS" -I{} bash -c 'check_one "$@"' _ {} \
    | awk -v total="$total" '{print; c++; if (c%500==0) printf("  ... %d/%d verwerkt\n", c, total) > "/dev/stderr"}' \
    > mx-results-raw.tsv
  log "  MX-lookup klaar: $(wc -l < mx-results-raw.tsv) regels"
}

# ---------------------------------------------------------------------------
# Stap 3: opschonen (dig-foutmeldingen, null-MX, kale IP's, lege MX-velden)
# ---------------------------------------------------------------------------
step3_clean() {
  log "Stap 3/5: brondata opschonen ..."

  # a) dig-foutfragmenten ("communications,no" e.d.) en null-MX/kaal-IP -> hostname_only
  awk -F'\t' '$2 !~ /communications|(^|,)\.$|(^|,)[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.?(,|$)/' \
    mx-results-raw.tsv > mx-tmp1.tsv

  # b) lege/komma-only MX-velden -> hostname_only
  awk -F'\t' '{ if ($2 ~ /^,*$/) print $1"\t-\thostname_only"; else print }' \
    mx-tmp1.tsv > mx-results.tsv

  rm -f mx-tmp1.tsv
  log "  opgeschoond: $(wc -l < mx-results.tsv) regels"
  log "  classificatie-verdeling:"
  awk -F'\t' '{print $3}' mx-results.tsv | sort | uniq -c | sort -rn | sed 's/^/    /' >&2
}

# ---------------------------------------------------------------------------
# Stap 4: eigenaarschap bepalen (EU / Microsoft / overige VS / overig / onbekend)
#          - alleen voor FQDN's met een echte, niet-zelfhostende MX
# ---------------------------------------------------------------------------
step4_owner() {
  log "Stap 4/5: eigenaarschap bepalen per MTA ..."
  write_owner_map

  lookup_owner() {
    local host="$1" classification="$2" domain="$3"
    local h="${host%.}"

    if [[ "$h" == *".${domain}" || "$h" == "$domain" ]]; then
      echo -e "EU\tEU-instelling (eigen infrastructuur)"
      return
    fi

    case "$classification" in
      microsoft)  echo -e "US\tMicrosoft Corporation (VS)"; return ;;
      google)     echo -e "US\tGoogle LLC (VS)"; return ;;
      proofpoint) echo -e "US\tProofpoint (VS)"; return ;;
      mimecast)   echo -e "OTHER\tMimecast (VK, dubbel VS/VK-hoofdkantoor)"; return ;;
    esac

    local best="" region="UNKNOWN" name="niet in mapping-tabel"
    while IFS=$'\t' read -r suffix reg nm; do
      if [[ "$h" == *"$suffix" ]]; then
        if [[ ${#suffix} -gt ${#best} ]]; then
          best="$suffix"; region="$reg"; name="$nm"
        fi
      fi
    done < owner-map.tsv
    echo -e "${region}\t${name}"
  }

  > mta-owner.tsv
  while IFS=$'\t' read -r fqdn mxlist classification; do
    [[ "$mxlist" == "-" ]] && continue
    IFS=',' read -ra mxs <<< "$mxlist"
    for mx in "${mxs[@]}"; do
      mx="${mx%.}"
      fqdn_clean="${fqdn%.}"
      [[ "$mx" == "$fqdn_clean" ]] && continue
      result=$(lookup_owner "$mx" "$classification" "$DOMAIN")
      echo -e "${fqdn_clean}\t${mx}\t${classification}\t${result}" >> mta-owner.tsv
    done
  done < mx-results.tsv

  log "  eigenaarschap bepaald voor $(cut -f1 mta-owner.tsv | sort -u | wc -l) unieke FQDN's"
}

# ---------------------------------------------------------------------------
# Stap 5: eindpresentatie
# ---------------------------------------------------------------------------
step5_report() {
  log "Stap 5/5: eindrapport opstellen ..."

  awk -F'\t' '{
    region=$4
    if (region=="US") { if ($3=="microsoft" || $5 ~ /Microsoft/) region="microsoft"; else region="us_other" }
    print $1"\t"region
  }' mta-owner.tsv | sort -u > fqdn-region.tsv

  local total_live total_mail
  total_live=$(wc -l < subdomains-live.txt)
  total_mail=$(wc -l < fqdn-region.tsv)

  echo >&2
  echo "================================================================" >&2
  echo " EINDRAPPORT — mailinfrastructuur onder *.${DOMAIN}" >&2
  echo "================================================================" >&2
  echo "Live subdomeinen onderzocht : $total_live" >&2
  echo "Subdomeinen met eigen MX    : $total_mail ($(awk -v a="$total_mail" -v b="$total_live" 'BEGIN{printf "%.1f", a/b*100}')%)" >&2
  echo >&2
  echo "Verdeling van die $total_mail subdomeinen naar eigenaar van de mailprovider:" >&2
  echo >&2
  awk -F'\t' '{print $2}' fqdn-region.tsv | sort | uniq -c | sort -rn | \
    awk -v total="$total_mail" '{printf "  %-12s %4d  (%.1f%%)\n", $2, $1, $1/total*100}' >&2
  echo >&2
  local us_total
  us_total=$(awk -F'\t' '$2=="microsoft" || $2=="us_other"' fqdn-region.tsv | wc -l)
  echo "  --> VS totaal (Microsoft + overig VS): $us_total ($(awk -v a="$us_total" -v b="$total_mail" 'BEGIN{printf "%.1f", a/b*100}')%)" >&2
  echo >&2
  echo "Nog niet in de mapping-tabel (owner-map.tsv aanvullen en stap 4+5 herhalen):" >&2
  awk -F'\t' '$2=="UNKNOWN"{print $1}' fqdn-region.tsv | sort -u | sed 's/^/    /' >&2
  echo "================================================================" >&2
  echo "Bestanden in $WORKDIR:" >&2
  echo "  subdomains-live.txt  - alle live subdomeinen" >&2
  echo "  mx-results.tsv       - fqdn / mx-lijst / classificatie (opgeschoond)" >&2
  echo "  mta-owner.tsv        - fqdn / mta / classificatie / regio / naam eigenaar" >&2
  echo "  fqdn-region.tsv      - fqdn / eindregio (eu, microsoft, us_other, other, unknown)" >&2
  echo "  owner-map.tsv        - curated eigenaarschap-tabel, uitbreidbaar" >&2
}

# ---------------------------------------------------------------------------
main() {
  log "Start onderzoek voor domein: $DOMAIN (werkdir: $WORKDIR)"
  step1_collect
  step2_mxcheck
  step3_clean
  step4_owner
  step5_report
  log "Klaar."
}

main
