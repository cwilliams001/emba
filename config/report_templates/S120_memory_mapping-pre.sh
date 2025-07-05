#!/bin/bash

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

# Description: Pre-report template for S120_memory_mapping module
#              Generates HTML report sections for memory mapping analysis

write_s120_log() {
  local lWRITE_S120_LOG_FILE="${LOG_DIR}""/s120_memory_mapping_log.txt"
  
  if [[ -f "${lWRITE_S120_LOG_FILE}" ]]; then
    if [[ "${THREADED}" -eq 1 ]]; then
      write_log "\\n\\n${MAGENTA}""${BOLD}""S120 Memory Mapping Analysis""${NC}""${MAGENTA}"" - ""${BOLD}""Runtime Address Extraction""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    else
      write_log "\\n\\n""${MAGENTA}""${BOLD}""S120 Memory Mapping Analysis""${NC}""${MAGENTA}"" - ""${BOLD}""Runtime Address Extraction""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    fi
    write_log "\\n\\n""${CYAN}""MEMORY MAPPING ANALYSIS:""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${BOLD}""This module extracts Runtime Addresses (RA) of critical binaries during emulation.""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${BOLD}""Key features:""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${ORANGE}""- Static memory layout analysis using readelf/objdump""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${ORANGE}""- Dynamic memory analysis from emulation /proc/maps""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${ORANGE}""- Runtime Address extraction for firmware comparison""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${ORANGE}""- ASLR implementation detection""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${ORANGE}""- Security analysis of memory layouts""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n\\n""${CYAN}""MEMORY MAPPING ANALYSIS RESULTS:""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n\\n" "${lWRITE_S120_LOG_FILE}"
    
    # Add specific sections for memory mapping results
    local lMEMORY_MAPPING_DIR="${LOG_DIR}/s120_memory_mapping"
    if [[ -d "${lMEMORY_MAPPING_DIR}" ]]; then
      if [[ -f "${lMEMORY_MAPPING_DIR}/runtime_addresses.csv" ]]; then
        local lRA_COUNT
        lRA_COUNT=$(grep -c -v "^BINARY," "${lMEMORY_MAPPING_DIR}/runtime_addresses.csv" 2>/dev/null || echo "0")
        write_log "\\n""${GREEN}""Runtime addresses extracted: ${lRA_COUNT}""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
        
        if [[ "${lRA_COUNT}" -gt 0 ]]; then
          write_log "\\n""${BOLD}""Critical binaries analyzed:""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
          
          # List unique binaries found
          local lUNIQUE_BINARIES
          lUNIQUE_BINARIES=$(grep -v "^BINARY," "${lMEMORY_MAPPING_DIR}/runtime_addresses.csv" 2>/dev/null | cut -d',' -f1 | sort -u)
          
          while IFS= read -r binary; do
            if [[ -n "${binary}" ]]; then
              write_log "\\n""${ORANGE}""- ${binary}""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
            fi
          done <<< "${lUNIQUE_BINARIES}"
          
          write_log "\\n\\n""${CYAN}""CSV Output Format:""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
          write_log "\\n""${BOLD}""BINARY,VERSION,BASE_ADDRESS,TEXT_START,DATA_START,BSS_START,HEAP_START,STACK_START,ANALYSIS_TYPE""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
        fi
      fi
      
      if [[ -f "${lMEMORY_MAPPING_DIR}/memory_mapping_report.txt" ]]; then
        write_log "\\n\\n""${CYAN}""Detailed memory mapping report available.""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
      fi
    fi
    
    write_log "\\n\\n""${CYAN}""USAGE FOR FIRMWARE COMPARISON:""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${BOLD}""To compare runtime addresses between firmware versions:""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${ORANGE}""1. Run EMBA with memory-mapping-analysis.emba profile on both versions""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${ORANGE}""2. Use helpers/compare_runtime_addresses.sh to compare results""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${ORANGE}""3. Review security analysis for ASLR implementation""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    
    write_log "\\n\\n""${CYAN}""SECURITY ANALYSIS:""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${BOLD}""This analysis helps identify:""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${ORANGE}""- ASLR implementation across firmware versions""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${ORANGE}""- Memory layout security improvements or regressions""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${ORANGE}""- Predictable vs randomized addressing patterns""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n""${ORANGE}""- Attack surface changes between firmware updates""${NC}""\\n" "${lWRITE_S120_LOG_FILE}"
    
    write_log "\\n\\n" "${lWRITE_S120_LOG_FILE}"
    write_log "\\n\\n" "${lWRITE_S120_LOG_FILE}"
    
  fi
}

write_s120_log 2>&1