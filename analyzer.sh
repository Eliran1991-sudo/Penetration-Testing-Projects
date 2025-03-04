#!/bin/bash
# -----------------------------------------------------------------------------------
# Student Name: Eliran Katri
# Student Code: s2
# Program Code: NX212
# Lecturer: Natali Erez
# Unit Code: CFC0324
# -----------------------------------------------------------------------------------
# PROJECT: ANALYZER (Windows Forensics) - Final with path logic
#
# This script automates analysis for both HDD and MEM, using Foremost, Bulk Extractor,
# Binwalk, Strings, and Volatility 2.6.
# It allows the user to type either a full path (/home/...) or just a filename
# (like harddisk.vmdk). If no slash is used, the script assumes /home/kali/analyzer_project.
# -----------------------------------------------------------------------------------

GREEN="\e[32m"
YELLOW="\e[33m"
MAGENTA="\e[35m"
CYAN="\e[36m"
BOLD="\e[1m"
RESET="\e[0m"

# 1. Must be root
if [ "$EUID" -ne 0 ]; then
  echo -e "${YELLOW}[!] Please run this script as root (or with sudo).${RESET}"
  exit 1
fi

# 2. Install needed tools if missing
check_or_install() {
  local CMD="$1"
  local PKG="$2"
  if ! command -v "$CMD" &>/dev/null; then
    echo -e "${YELLOW}[#] '$CMD' not found, installing '$PKG'...${RESET}"
    apt-get install -y "$PKG" &>/dev/null
    echo -e "${GREEN}[#] '$PKG' installation complete.${RESET}"
  fi
}

echo -e "${YELLOW}Checking & Installing needed tools...${RESET}"
check_or_install "figlet" "figlet"

declare -A tool_map=(
  ["bulk_extractor"]="bulk-extractor"
  ["binwalk"]="binwalk"
  ["foremost"]="foremost"
  ["strings"]="binutils"
)
for cmd in "${!tool_map[@]}"; do
  check_or_install "$cmd" "${tool_map[$cmd]}"
done

# Print banner
echo -e "${CYAN}"
figlet -f slant "PROJECT: ANALYZER"
echo -e "${RESET}"

# Base folder
RESULTS_BASE="/home/kali/analyzer_project/forensic_results"
mkdir -p "$RESULTS_BASE"

echo -e "${YELLOW}Note:${RESET} Using Volatility 2.6 in '~/volatility'. \nIf 'No valid profile' occurs, dump may be incompatible.\n"

while true; do
  echo -e "${MAGENTA}Enter the file name or full path (or 'exit' to quit):${RESET}"
  read -r USR_INPUT
  if [ "$USR_INPUT" = "exit" ]; then
    echo -e "${YELLOW}Exiting. Goodbye!${RESET}"
    break
  fi

  # -- HERE is the path logic --
  # If user input doesn't start with '/', assume /home/kali/analyzer_project
  if [[ "$USR_INPUT" != /* ]]; then
    FILE="/home/kali/analyzer_project/$USR_INPUT"
  else
    FILE="$USR_INPUT"
  fi

  # Check existence
  if [ ! -f "$FILE" ]; then
    echo -e "${YELLOW}[!] File '$FILE' not found. Try again.${RESET}"
    continue
  fi

  # Create output dir
  OUTPUT_DIR="$RESULTS_BASE/analysis_output_$(date +%Y%m%d_%H%M%S)"
  mkdir "$OUTPUT_DIR"
  echo -e "${MAGENTA}\n[*] Created output directory: $OUTPUT_DIR${RESET}"

  START_TIME=$(date +%s)

  # Decide if memory or HDD
  IS_MEM=false
  if [[ "$FILE" =~ \.mem$ ]]; then
    IS_MEM=true
  fi

  if $IS_MEM; then
    echo -e "${CYAN}[*] Memory Analysis (Volatility2.6 from ~/volatility)...${RESET}"

    ( cd /home/kali/volatility && python2.7 vol.py -f "$FILE" imageinfo ) &> "$OUTPUT_DIR/imageinfo.txt"
    SUGGESTED=$(grep -i "Suggested Profile" "$OUTPUT_DIR/imageinfo.txt" | sed 's/.*: //; s/,.*//')

    if [ -n "$SUGGESTED" ]; then
      echo -e "${GREEN}[+] Found suggested profile(s): $SUGGESTED${RESET}"
      PROFILE=$(echo "$SUGGESTED" | awk '{print $1}')
      echo "[*] Using profile: $PROFILE"

      # minimal plugin
      ( cd /home/kali/volatility && python2.7 vol.py -f "$FILE" --profile="$PROFILE" pslist ) &> "$OUTPUT_DIR/pslist.txt"
    else
      echo -e "${YELLOW}[-] No valid Volatility profile found; maybe unsupported dump?${RESET}"
    fi

    REPORT="$OUTPUT_DIR/report.txt"
    {
      echo "===== PROJECT: ANALYZER - Memory Minimal Report ====="
      echo "Date: $(date)"
      echo "File: $FILE"
      echo "Suggested Profiles: $SUGGESTED"
      echo "pslist -> $OUTPUT_DIR/pslist.txt"
    } > "$REPORT"

  else
    echo -e "${CYAN}[*] HDD Analysis (Foremost, Bulk, Binwalk)...${RESET}"

    # Foremost
    foremost -i "$FILE" -o "$OUTPUT_DIR/foremost_out" &> "$OUTPUT_DIR/foremost.log"
    # Bulk
    bulk_extractor -o "$OUTPUT_DIR/bulk_out" "$FILE" &> "$OUTPUT_DIR/bulk_extractor.log"
    # Binwalk
    binwalk -e -q -C "$OUTPUT_DIR/binwalk_out" --run-as=root "$FILE" &> "$OUTPUT_DIR/binwalk.log"

    PCAPS=$(find "$OUTPUT_DIR/bulk_out" -iname "*.pcap" 2>/dev/null)
    if [ -n "$PCAPS" ]; then
      echo "[+] Found PCAP in bulk_out:"
      echo "$PCAPS"
      du -sh $PCAPS
    else
      echo "[-] No PCAP found."
    fi

    strings "$FILE" | grep -iE "password|username" > "$OUTPUT_DIR/strings_pass_user.txt"
    if [ -s "$OUTPUT_DIR/strings_pass_user.txt" ]; then
      echo "[+] Found potential sensitive strings in: $OUTPUT_DIR/strings_pass_user.txt"
    else
      rm "$OUTPUT_DIR/strings_pass_user.txt"
      echo "[-] No 'password' or 'username' found."
    fi

    NumForemost=$(find "$OUTPUT_DIR/foremost_out" -type f 2>/dev/null | wc -l)
    NumBulk=$(find "$OUTPUT_DIR/bulk_out" -type f 2>/dev/null | wc -l)
    NumBinwalk=$(find "$OUTPUT_DIR/binwalk_out" -type f 2>/dev/null | wc -l)

    REPORT="$OUTPUT_DIR/report.txt"
    {
      echo "===== PROJECT: ANALYZER - HDD Minimal Report ====="
      echo "Date: $(date)"
      echo "File: $FILE"
      echo "----------------------------------------------"
      echo "Foremost out -> $OUTPUT_DIR/foremost_out ($NumForemost files)"
      echo "Bulk out -> $OUTPUT_DIR/bulk_out       ($NumBulk files)"
      echo "Binwalk out -> $OUTPUT_DIR/binwalk_out ($NumBinwalk files)"
    } > "$REPORT"
  fi

  END_TIME=$(date +%s)
  DURATION=$((END_TIME - START_TIME))
  MINUTES=$((DURATION / 60))
  SECONDS=$((DURATION % 60))

  {
    echo "----------------------------------------------"
    echo "Analysis took: ${MINUTES}m ${SECONDS}s."
  } >> "$REPORT"

  ZIPFILE="$OUTPUT_DIR.zip"
  zip -r "$ZIPFILE" "$OUTPUT_DIR" &>/dev/null

  echo -e "${GREEN}\n[#] Analysis of '$FILE' completed!${RESET}"
  echo "Check the folder: $OUTPUT_DIR"
  echo "And the ZIP file: $ZIPFILE"
  echo -e "${MAGENTA}-----------------------------------\n${RESET}"
done

echo -e "${GREEN}Script ended.${RESET}"
figlet -f slant "GOODBYE!"
