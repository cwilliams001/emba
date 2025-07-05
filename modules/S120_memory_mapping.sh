#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Claude Code Assistant

# Description:  Memory mapping analysis module for extracting Runtime Addresses (RA) 
#               of critical binaries during emulation. This module focuses on uclibc, 
#               httpd, and other system binaries to support firmware version comparison.

# Threading priority - if set to 1, these modules will be executed first
export THREAD_PRIO=0

: <<'END_OF_DOCS'
=pod

=head1 S120_memory_mapping

=head2 S120_memory_mapping Short description

Extracts Runtime Addresses (RA) of critical binaries during emulation to support firmware version comparison and security analysis.

=head2 S120_memory_mapping Detailed description

This module analyzes memory layouts of critical system binaries (uclibc, httpd, etc.) during emulation to extract Runtime Addresses.
It supports both static analysis using readelf/objdump and dynamic analysis during emulation phases.
The module generates standardized RA output for cross-version comparison to detect ASLR implementation,
memory layout security improvements, and attack surface changes between firmware versions.

=head2 S120_memory_mapping 3rd party tools

- readelf (from binutils)
- objdump (from binutils)  
- cat (for /proc/maps parsing during emulation)
- grep, awk, sed (standard utilities)

=head2 S120_memory_mapping Output

Runtime Address extraction for uclibc, httpd, and other critical binaries in CSV format:
BINARY,VERSION,BASE_ADDRESS,TEXT_START,DATA_START,BSS_START,HEAP_START,STACK_START

=head2 S120_memory_mapping License

EMBA module S120_memory_mapping is licensed under GPLv3
SPDX-License-Identifier: GPL-3.0-only

=head2 S120_memory_mapping Author(s)

Claude Code Assistant

=cut

END_OF_DOCS

S120_memory_mapping() {
  local lNEG_LOG=0
  local lMEMORY_FINDINGS_COUNT=0
  local lCRIT_BINARIES_ARR=()
  local lBINARY=""
  local lRA_OUTPUT_FILE=""
  local lMEMORY_MAPS_DIR=""
  local lSTATIC_ANALYSIS_FILE=""
  local lDYNAMIC_ANALYSIS_FILE=""
  
  module_log_init "${FUNCNAME[0]}"
  module_title "Memory Mapping Analysis for Critical Binaries"
  pre_module_reporter "${FUNCNAME[0]}"

  # Critical binaries to analyze for Runtime Address extraction
  lCRIT_BINARIES_ARR=("uclibc" "httpd" "busybox" "dropbear" "lighttpd" "nginx" "telnetd" "sshd" "ftpd" "dhcpd")
  
  # Create output directories
  lMEMORY_MAPS_DIR="${LOG_PATH_MODULE}/memory_maps"
  mkdir -p "${lMEMORY_MAPS_DIR}"
  
  # Output files
  lRA_OUTPUT_FILE="${LOG_PATH_MODULE}/runtime_addresses.csv"
  lSTATIC_ANALYSIS_FILE="${LOG_PATH_MODULE}/static_memory_analysis.txt"
  lDYNAMIC_ANALYSIS_FILE="${LOG_PATH_MODULE}/dynamic_memory_analysis.txt"
  
  print_output "[*] Starting memory mapping analysis for critical binaries"
  print_output "[*] Target binaries: ${lCRIT_BINARIES_ARR[*]}"
  
  # Initialize CSV output with headers
  echo "BINARY,VERSION,BASE_ADDRESS,TEXT_START,DATA_START,BSS_START,HEAP_START,STACK_START,ANALYSIS_TYPE" > "${lRA_OUTPUT_FILE}"
  
  # Perform static analysis
  print_output "[*] Performing static memory layout analysis..."
  perform_static_memory_analysis "${lCRIT_BINARIES_ARR[@]}"
  
  # Perform dynamic analysis if emulation data is available
  if [[ -d "${LOG_DIR}/s115_usermode_emulator" ]] || [[ -d "${LOG_DIR}/l10_system_emulation" ]]; then
    print_output "[*] Emulation data detected - performing dynamic memory analysis..."
    perform_dynamic_memory_analysis "${lCRIT_BINARIES_ARR[@]}"
  else
    print_output "[*] No emulation data available - skipping dynamic analysis"
  fi
  
  # Generate memory mapping report
  generate_memory_mapping_report
  
  # Count findings
  if [[ -f "${lRA_OUTPUT_FILE}" ]]; then
    lMEMORY_FINDINGS_COUNT=$(grep -c -v "^BINARY," "${lRA_OUTPUT_FILE}" 2>/dev/null || echo "0")
  fi
  
  if [[ "${lMEMORY_FINDINGS_COUNT}" -gt 0 ]]; then
    print_output "[+] Memory mapping analysis completed - ${ORANGE}${lMEMORY_FINDINGS_COUNT}${GREEN} runtime addresses extracted"
    lNEG_LOG=1
  else
    print_output "[-] No memory mapping data extracted"
  fi
  
  module_end_log "${FUNCNAME[0]}" "${lMEMORY_FINDINGS_COUNT}"
}

perform_static_memory_analysis() {
  local lCRIT_BINARIES_ARR=("$@")
  local lBINARY=""
  local lFOUND_BINARIES_ARR=()
  local lBIN_FILE=""
  local lBINARY_VERSION=""
  local lBASE_ADDR=""
  local lTEXT_START=""
  local lDATA_START=""
  local lBSS_START=""
  
  sub_module_title "Static Memory Layout Analysis"
  
  # Search for critical binaries in the firmware
  for lBINARY in "${lCRIT_BINARIES_ARR[@]}"; do
    print_output "[*] Searching for ${lBINARY} binaries..."
    
    # Use find to locate binaries, excluding certain paths
    mapfile -t lFOUND_BINARIES_ARR < <(find "${FIRMWARE_PATH}" "${EXCL_FIND[@]}" -type f -name "*${lBINARY}*" -executable 2>/dev/null)
    
    for lBIN_FILE in "${lFOUND_BINARIES_ARR[@]}"; do
      if [[ -f "${lBIN_FILE}" ]]; then
        # Check if it's actually an ELF binary
        if file "${lBIN_FILE}" 2>/dev/null | grep -q "ELF.*executable\|ELF.*shared object"; then
          print_output "[+] Found ELF binary: $(print_path "${lBIN_FILE}")"
          
          # Extract static memory layout information
          analyze_static_memory_layout "${lBIN_FILE}" "${lBINARY}"
        fi
      fi
    done
  done
  
  print_output "[*] Static memory analysis completed"
}

analyze_static_memory_layout() {
  local lBIN_FILE="${1:-}"
  local lBINARY_NAME="${2:-}"
  local lBINARY_VERSION=""
  local lBASE_ADDR=""
  local lTEXT_START=""
  local lDATA_START=""
  local lBSS_START=""
  local lENTRY_POINT=""
  local lARCH_INFO=""
  
  if [[ ! -f "${lBIN_FILE}" ]]; then
    return
  fi
  
  print_output "[*] Analyzing static memory layout for ${lBIN_FILE}"
  
  # Extract binary version if available
  lBINARY_VERSION=$(strings "${lBIN_FILE}" 2>/dev/null | grep -i "version\|v[0-9]" | head -1 | tr -d '\0' | cut -c1-20 || echo "unknown")
  
  # Get architecture info
  lARCH_INFO=$(readelf -h "${lBIN_FILE}" 2>/dev/null | grep -E "Class|Machine" | tr '\n' ' ' || echo "unknown")
  
  # Extract memory layout information using readelf
  if command -v readelf >/dev/null 2>&1; then
    # Get entry point
    lENTRY_POINT=$(readelf -h "${lBIN_FILE}" 2>/dev/null | grep "Entry point address" | awk '{print $4}' || echo "0x0")
    
    # Get section headers for memory layout
    local lSECTION_INFO=""
    lSECTION_INFO=$(readelf -S "${lBIN_FILE}" 2>/dev/null)
    
    # Extract key section addresses
    lTEXT_START=$(echo "${lSECTION_INFO}" | grep -w "\.text" | awk '{print $4}' | head -1 || echo "0x0")
    lDATA_START=$(echo "${lSECTION_INFO}" | grep -w "\.data" | awk '{print $4}' | head -1 || echo "0x0")
    lBSS_START=$(echo "${lSECTION_INFO}" | grep -w "\.bss" | awk '{print $4}' | head -1 || echo "0x0")
    
    # Use entry point as base address if available
    lBASE_ADDR="${lENTRY_POINT}"
    
    # Log detailed information
    {
      echo "Binary: ${lBIN_FILE}"
      echo "Architecture: ${lARCH_INFO}"
      echo "Entry Point: ${lENTRY_POINT}"
      echo "Text Section: ${lTEXT_START}"
      echo "Data Section: ${lDATA_START}"
      echo "BSS Section: ${lBSS_START}"
      echo "---"
    } >> "${lSTATIC_ANALYSIS_FILE}"
    
    # Add to CSV output
    echo "${lBINARY_NAME},${lBINARY_VERSION},${lBASE_ADDR},${lTEXT_START},${lDATA_START},${lBSS_START},N/A,N/A,static" >> "${lRA_OUTPUT_FILE}"
    
    print_output "[+] Static analysis completed for ${lBINARY_NAME} - Base: ${lBASE_ADDR}, Text: ${lTEXT_START}"
  else
    print_output "[-] readelf not available - skipping static analysis"
  fi
}

perform_dynamic_memory_analysis() {
  local lCRIT_BINARIES_ARR=("$@")
  local lBINARY=""
  local lEMULATION_LOGS_ARR=()
  local lEMU_LOG=""
  local lPROC_MAPS_FILE=""
  
  sub_module_title "Dynamic Memory Layout Analysis"
  
  # Look for emulation logs that might contain memory mapping information
  mapfile -t lEMULATION_LOGS_ARR < <(find "${LOG_DIR}" -name "*emulation*" -type d 2>/dev/null)
  
  for lEMU_LOG in "${lEMULATION_LOGS_ARR[@]}"; do
    if [[ -d "${lEMU_LOG}" ]]; then
      print_output "[*] Analyzing emulation logs in ${lEMU_LOG}"
      
      # Look for process memory maps
      mapfile -t lPROC_MAPS_FILES < <(find "${lEMU_LOG}" -name "*maps*" -o -name "*memory*" -type f 2>/dev/null)
      
      for lPROC_MAPS_FILE in "${lPROC_MAPS_FILES[@]}"; do
        if [[ -f "${lPROC_MAPS_FILE}" ]]; then
          analyze_dynamic_memory_maps "${lPROC_MAPS_FILE}" "${lCRIT_BINARIES_ARR[@]}"
        fi
      done
    fi
  done
  
  # Also check for any /proc/maps files in the emulation filesystem
  if [[ -d "${EMULATION_PATH_BASE}" ]]; then
    mapfile -t lPROC_MAPS_FILES < <(find "${EMULATION_PATH_BASE}" -path "*/proc/*/maps" -type f 2>/dev/null)
    
    for lPROC_MAPS_FILE in "${lPROC_MAPS_FILES[@]}"; do
      if [[ -f "${lPROC_MAPS_FILE}" ]]; then
        analyze_dynamic_memory_maps "${lPROC_MAPS_FILE}" "${lCRIT_BINARIES_ARR[@]}"
      fi
    done
  fi
  
  print_output "[*] Dynamic memory analysis completed"
}

analyze_dynamic_memory_maps() {
  local lPROC_MAPS_FILE="${1:-}"
  shift
  local lCRIT_BINARIES_ARR=("$@")
  local lBINARY=""
  local lMAPS_CONTENT=""
  local lBINARY_MAPS=""
  local lBASE_ADDR=""
  local lTEXT_START=""
  local lDATA_START=""
  local lHEAP_START=""
  local lSTACK_START=""
  
  if [[ ! -f "${lPROC_MAPS_FILE}" ]]; then
    return
  fi
  
  print_output "[*] Analyzing dynamic memory maps from ${lPROC_MAPS_FILE}"
  
  lMAPS_CONTENT=$(cat "${lPROC_MAPS_FILE}" 2>/dev/null)
  
  if [[ -z "${lMAPS_CONTENT}" ]]; then
    return
  fi
  
  for lBINARY in "${lCRIT_BINARIES_ARR[@]}"; do
    # Look for binary in memory maps
    lBINARY_MAPS=$(echo "${lMAPS_CONTENT}" | grep -i "${lBINARY}" 2>/dev/null)
    
    if [[ -n "${lBINARY_MAPS}" ]]; then
      print_output "[+] Found ${lBINARY} in memory maps"
      
      # Extract memory addresses from maps
      lBASE_ADDR=$(echo "${lBINARY_MAPS}" | head -1 | cut -d'-' -f1)
      lTEXT_START=$(echo "${lBINARY_MAPS}" | grep -E "r-xp|r.x." | head -1 | cut -d'-' -f1 || echo "${lBASE_ADDR}")
      lDATA_START=$(echo "${lBINARY_MAPS}" | grep -E "rw-p|rw.." | head -1 | cut -d'-' -f1 || echo "0x0")
      
      # Look for heap and stack
      lHEAP_START=$(echo "${lMAPS_CONTENT}" | grep -w "heap" | head -1 | cut -d'-' -f1 || echo "0x0")
      lSTACK_START=$(echo "${lMAPS_CONTENT}" | grep -w "stack" | head -1 | cut -d'-' -f1 || echo "0x0")
      
      # Log detailed information
      {
        echo "Binary: ${lBINARY}"
        echo "Source: ${lPROC_MAPS_FILE}"
        echo "Base Address: 0x${lBASE_ADDR}"
        echo "Text Section: 0x${lTEXT_START}"
        echo "Data Section: 0x${lDATA_START}"
        echo "Heap Start: 0x${lHEAP_START}"
        echo "Stack Start: 0x${lSTACK_START}"
        echo "Raw maps:"
        echo "${lBINARY_MAPS}"
        echo "---"
      } >> "${lDYNAMIC_ANALYSIS_FILE}"
      
      # Add to CSV output
      echo "${lBINARY},dynamic,0x${lBASE_ADDR},0x${lTEXT_START},0x${lDATA_START},0x0,0x${lHEAP_START},0x${lSTACK_START},dynamic" >> "${lRA_OUTPUT_FILE}"
      
      print_output "[+] Dynamic analysis completed for ${lBINARY} - Base: 0x${lBASE_ADDR}, Text: 0x${lTEXT_START}"
    fi
  done
}

generate_memory_mapping_report() {
  local lREPORT_FILE="${LOG_PATH_MODULE}/memory_mapping_report.txt"
  local lRA_COUNT=0
  local lUNIQUE_BINARIES=0
  
  sub_module_title "Memory Mapping Report Generation"
  
  if [[ ! -f "${lRA_OUTPUT_FILE}" ]]; then
    print_output "[-] No runtime address data available for report generation"
    return
  fi
  
  lRA_COUNT=$(grep -c -v "^BINARY," "${lRA_OUTPUT_FILE}" 2>/dev/null || echo "0")
  lUNIQUE_BINARIES=$(grep -v "^BINARY," "${lRA_OUTPUT_FILE}" 2>/dev/null | cut -d',' -f1 | sort -u | wc -l || echo "0")
  
  {
    echo "EMBA Memory Mapping Analysis Report"
    echo "=================================="
    echo "Generated: $(date)"
    echo "Firmware: ${FIRMWARE_PATH}"
    echo ""
    echo "Summary:"
    echo "- Total Runtime Addresses Extracted: ${lRA_COUNT}"
    echo "- Unique Binaries Analyzed: ${lUNIQUE_BINARIES}"
    echo ""
    echo "Critical Binaries Found:"
    if [[ -f "${lRA_OUTPUT_FILE}" ]]; then
      grep -v "^BINARY," "${lRA_OUTPUT_FILE}" | cut -d',' -f1 | sort -u | while read -r lBINARY; do
        echo "- ${lBINARY}"
      done
    fi
    echo ""
    echo "Memory Layout Analysis:"
    echo "======================"
    if [[ -f "${lSTATIC_ANALYSIS_FILE}" ]]; then
      cat "${lSTATIC_ANALYSIS_FILE}"
    fi
    echo ""
    echo "Dynamic Memory Analysis:"
    echo "======================="
    if [[ -f "${lDYNAMIC_ANALYSIS_FILE}" ]]; then
      cat "${lDYNAMIC_ANALYSIS_FILE}"
    fi
    echo ""
    echo "CSV Output Available: ${lRA_OUTPUT_FILE}"
    echo "Use this data for firmware version comparison and ASLR analysis"
  } > "${lREPORT_FILE}"
  
  print_output "[+] Memory mapping report generated: ${lREPORT_FILE}"
  print_output "[+] Runtime addresses CSV: ${lRA_OUTPUT_FILE}"
}