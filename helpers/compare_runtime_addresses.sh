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

# Description: Helper script to compare Runtime Addresses (RA) between firmware versions
#              Analyzes memory layout changes, ASLR implementation, and security improvements

usage() {
    echo "Usage: $0 <log_dir_v1> <log_dir_v2> [output_dir]"
    echo ""
    echo "Compare Runtime Addresses between two firmware versions"
    echo ""
    echo "Arguments:"
    echo "  log_dir_v1   Path to first firmware analysis log directory"
    echo "  log_dir_v2   Path to second firmware analysis log directory"
    echo "  output_dir   Optional output directory (defaults to current directory)"
    echo ""
    echo "Example:"
    echo "  $0 logs_v1.0 logs_v1.1 comparison_output"
    echo ""
    exit 1
}

# Check arguments
if [[ $# -lt 2 ]]; then
    usage
fi

LOG_DIR_V1="$1"
LOG_DIR_V2="$2"
OUTPUT_DIR="${3:-$(pwd)/ra_comparison_$(date +%Y%m%d_%H%M%S)}"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_output() {
    echo -e "$1"
}

# Validate input directories
if [[ ! -d "$LOG_DIR_V1" ]]; then
    print_output "${RED}[-] Error: Log directory $LOG_DIR_V1 does not exist${NC}"
    exit 1
fi

if [[ ! -d "$LOG_DIR_V2" ]]; then
    print_output "${RED}[-] Error: Log directory $LOG_DIR_V2 does not exist${NC}"
    exit 1
fi

# Look for S120 module output files
RA_FILE_V1=$(find "$LOG_DIR_V1" -name "runtime_addresses.csv" -path "*/s120_memory_mapping/*" 2>/dev/null | head -1)
RA_FILE_V2=$(find "$LOG_DIR_V2" -name "runtime_addresses.csv" -path "*/s120_memory_mapping/*" 2>/dev/null | head -1)

if [[ ! -f "$RA_FILE_V1" ]]; then
    print_output "${RED}[-] Error: Runtime addresses file not found in $LOG_DIR_V1${NC}"
    print_output "${YELLOW}[!] Make sure the S120_memory_mapping module was executed${NC}"
    exit 1
fi

if [[ ! -f "$RA_FILE_V2" ]]; then
    print_output "${RED}[-] Error: Runtime addresses file not found in $LOG_DIR_V2${NC}"
    print_output "${YELLOW}[!] Make sure the S120_memory_mapping module was executed${NC}"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

print_output "${GREEN}[+] Starting Runtime Address comparison${NC}"
print_output "${CYAN}[*] Version 1: $LOG_DIR_V1${NC}"
print_output "${CYAN}[*] Version 2: $LOG_DIR_V2${NC}"
print_output "${CYAN}[*] Output directory: $OUTPUT_DIR${NC}"

# Analysis functions
analyze_aslr_implementation() {
    local version1_file="$1"
    local version2_file="$2"
    local output_file="$3"
    
    print_output "${BLUE}[*] Analyzing ASLR implementation...${NC}"
    
    {
        echo "ASLR Implementation Analysis"
        echo "==========================="
        echo "Generated: $(date)"
        echo ""
        
        # Extract unique binaries from both versions
        local binaries_v1=$(grep -v "^BINARY," "$version1_file" 2>/dev/null | cut -d',' -f1 | sort -u)
        local binaries_v2=$(grep -v "^BINARY," "$version2_file" 2>/dev/null | cut -d',' -f1 | sort -u)
        
        echo "Binaries in Version 1: $(echo "$binaries_v1" | wc -l)"
        echo "Binaries in Version 2: $(echo "$binaries_v2" | wc -l)"
        echo ""
        
        echo "Address Randomization Analysis:"
        echo "==============================="
        
        # Compare addresses for common binaries
        for binary in $binaries_v1; do
            if echo "$binaries_v2" | grep -q "^$binary$"; then
                echo "Binary: $binary"
                
                # Get addresses from both versions
                local v1_addrs=$(grep "^$binary," "$version1_file" | cut -d',' -f3-6)
                local v2_addrs=$(grep "^$binary," "$version2_file" | cut -d',' -f3-6)
                
                echo "  Version 1: $v1_addrs"
                echo "  Version 2: $v2_addrs"
                
                # Check if addresses changed
                if [[ "$v1_addrs" == "$v2_addrs" ]]; then
                    echo "  Status: STATIC - No address randomization detected"
                else
                    echo "  Status: DYNAMIC - Address randomization detected"
                fi
                echo ""
            fi
        done
        
    } > "$output_file"
    
    print_output "${GREEN}[+] ASLR analysis completed: $output_file${NC}"
}

generate_address_diff_report() {
    local version1_file="$1"
    local version2_file="$2"
    local output_file="$3"
    
    print_output "${BLUE}[*] Generating address difference report...${NC}"
    
    {
        echo "Runtime Address Differences Report"
        echo "================================="
        echo "Generated: $(date)"
        echo ""
        
        # Header
        printf "%-15s %-12s %-12s %-12s %-12s %-12s\n" "BINARY" "V1_BASE" "V2_BASE" "V1_TEXT" "V2_TEXT" "DIFF_STATUS"
        printf "%-15s %-12s %-12s %-12s %-12s %-12s\n" "===============" "============" "============" "============" "============" "============"
        
        # Compare addresses
        local binaries_v1=$(grep -v "^BINARY," "$version1_file" 2>/dev/null | cut -d',' -f1 | sort -u)
        
        for binary in $binaries_v1; do
            local v1_line=$(grep "^$binary," "$version1_file" | head -1)
            local v2_line=$(grep "^$binary," "$version2_file" | head -1)
            
            if [[ -n "$v1_line" ]] && [[ -n "$v2_line" ]]; then
                local v1_base=$(echo "$v1_line" | cut -d',' -f3)
                local v1_text=$(echo "$v1_line" | cut -d',' -f4)
                local v2_base=$(echo "$v2_line" | cut -d',' -f3)
                local v2_text=$(echo "$v2_line" | cut -d',' -f4)
                
                local diff_status="SAME"
                if [[ "$v1_base" != "$v2_base" ]] || [[ "$v1_text" != "$v2_text" ]]; then
                    diff_status="DIFFERENT"
                fi
                
                printf "%-15s %-12s %-12s %-12s %-12s %-12s\n" "$binary" "$v1_base" "$v2_base" "$v1_text" "$v2_text" "$diff_status"
            fi
        done
        
        echo ""
        echo "Summary:"
        echo "========"
        local total_binaries=$(echo "$binaries_v1" | wc -l)
        local different_count=0
        
        for binary in $binaries_v1; do
            local v1_line=$(grep "^$binary," "$version1_file" | head -1)
            local v2_line=$(grep "^$binary," "$version2_file" | head -1)
            
            if [[ -n "$v1_line" ]] && [[ -n "$v2_line" ]]; then
                local v1_base=$(echo "$v1_line" | cut -d',' -f3)
                local v1_text=$(echo "$v1_line" | cut -d',' -f4)
                local v2_base=$(echo "$v2_line" | cut -d',' -f3)
                local v2_text=$(echo "$v2_line" | cut -d',' -f4)
                
                if [[ "$v1_base" != "$v2_base" ]] || [[ "$v1_text" != "$v2_text" ]]; then
                    ((different_count++))
                fi
            fi
        done
        
        echo "- Total binaries compared: $total_binaries"
        echo "- Binaries with different addresses: $different_count"
        echo "- Binaries with same addresses: $((total_binaries - different_count))"
        
        if [[ $different_count -gt 0 ]]; then
            echo "- ASLR Implementation: LIKELY (addresses changed between versions)"
        else
            echo "- ASLR Implementation: UNLIKELY (addresses remained static)"
        fi
        
    } > "$output_file"
    
    print_output "${GREEN}[+] Address difference report completed: $output_file${NC}"
}

generate_security_analysis() {
    local version1_file="$1"
    local version2_file="$2"
    local output_file="$3"
    
    print_output "${BLUE}[*] Generating security analysis...${NC}"
    
    {
        echo "Security Analysis Report"
        echo "======================"
        echo "Generated: $(date)"
        echo ""
        
        echo "Memory Layout Security Assessment:"
        echo "================================="
        
        # Analyze critical binaries
        local critical_binaries=("uclibc" "httpd" "busybox" "dropbear" "sshd")
        
        for binary in "${critical_binaries[@]}"; do
            local v1_line=$(grep "^$binary," "$version1_file" | head -1)
            local v2_line=$(grep "^$binary," "$version2_file" | head -1)
            
            if [[ -n "$v1_line" ]] && [[ -n "$v2_line" ]]; then
                echo "Critical Binary: $binary"
                
                local v1_base=$(echo "$v1_line" | cut -d',' -f3)
                local v2_base=$(echo "$v2_line" | cut -d',' -f3)
                
                echo "  Version 1 Base: $v1_base"
                echo "  Version 2 Base: $v2_base"
                
                # Check for predictable addresses
                if [[ "$v1_base" == "0x00400000" ]] || [[ "$v2_base" == "0x00400000" ]]; then
                    echo "  Security Risk: HIGH - Predictable base address detected"
                elif [[ "$v1_base" == "$v2_base" ]]; then
                    echo "  Security Risk: MEDIUM - Static address layout"
                else
                    echo "  Security Risk: LOW - Address randomization implemented"
                fi
                echo ""
            fi
        done
        
        echo "Attack Surface Analysis:"
        echo "======================="
        
        # Check for new/removed binaries
        local binaries_v1=$(grep -v "^BINARY," "$version1_file" 2>/dev/null | cut -d',' -f1 | sort -u)
        local binaries_v2=$(grep -v "^BINARY," "$version2_file" 2>/dev/null | cut -d',' -f1 | sort -u)
        
        echo "New binaries in Version 2:"
        comm -13 <(echo "$binaries_v1") <(echo "$binaries_v2") | while read -r binary; do
            echo "  + $binary"
        done
        
        echo ""
        echo "Removed binaries in Version 2:"
        comm -23 <(echo "$binaries_v1") <(echo "$binaries_v2") | while read -r binary; do
            echo "  - $binary"
        done
        
        echo ""
        echo "Security Recommendations:"
        echo "========================"
        echo "- Review address randomization implementation"
        echo "- Verify ASLR is enabled in kernel configuration"
        echo "- Monitor changes in critical system binaries"
        echo "- Test exploit mitigation effectiveness"
        
    } > "$output_file"
    
    print_output "${GREEN}[+] Security analysis completed: $output_file${NC}"
}

# Main analysis execution
print_output "${CYAN}[*] Processing Runtime Address files...${NC}"

# Generate comparison reports
analyze_aslr_implementation "$RA_FILE_V1" "$RA_FILE_V2" "$OUTPUT_DIR/aslr_analysis.txt"
generate_address_diff_report "$RA_FILE_V1" "$RA_FILE_V2" "$OUTPUT_DIR/address_differences.txt"
generate_security_analysis "$RA_FILE_V1" "$RA_FILE_V2" "$OUTPUT_DIR/security_analysis.txt"

# Create a combined CSV for easy comparison
print_output "${BLUE}[*] Creating combined comparison CSV...${NC}"
{
    echo "BINARY,V1_BASE,V1_TEXT,V1_DATA,V2_BASE,V2_TEXT,V2_DATA,CHANGED"
    
    local binaries_v1=$(grep -v "^BINARY," "$RA_FILE_V1" 2>/dev/null | cut -d',' -f1 | sort -u)
    
    for binary in $binaries_v1; do
        local v1_line=$(grep "^$binary," "$RA_FILE_V1" | head -1)
        local v2_line=$(grep "^$binary," "$RA_FILE_V2" | head -1)
        
        if [[ -n "$v1_line" ]] && [[ -n "$v2_line" ]]; then
            local v1_base=$(echo "$v1_line" | cut -d',' -f3)
            local v1_text=$(echo "$v1_line" | cut -d',' -f4)
            local v1_data=$(echo "$v1_line" | cut -d',' -f5)
            local v2_base=$(echo "$v2_line" | cut -d',' -f3)
            local v2_text=$(echo "$v2_line" | cut -d',' -f4)
            local v2_data=$(echo "$v2_line" | cut -d',' -f5)
            
            local changed="NO"
            if [[ "$v1_base" != "$v2_base" ]] || [[ "$v1_text" != "$v2_text" ]] || [[ "$v1_data" != "$v2_data" ]]; then
                changed="YES"
            fi
            
            echo "$binary,$v1_base,$v1_text,$v1_data,$v2_base,$v2_text,$v2_data,$changed"
        fi
    done
    
} > "$OUTPUT_DIR/combined_comparison.csv"

print_output "${GREEN}[+] Combined comparison CSV created: $OUTPUT_DIR/combined_comparison.csv${NC}"

# Generate summary report
print_output "${BLUE}[*] Generating summary report...${NC}"
{
    echo "EMBA Runtime Address Comparison Summary"
    echo "======================================"
    echo "Generated: $(date)"
    echo ""
    echo "Analysis Files:"
    echo "- Version 1: $LOG_DIR_V1"
    echo "- Version 2: $LOG_DIR_V2"
    echo "- RA File 1: $RA_FILE_V1"
    echo "- RA File 2: $RA_FILE_V2"
    echo ""
    echo "Output Files:"
    echo "- ASLR Analysis: $OUTPUT_DIR/aslr_analysis.txt"
    echo "- Address Differences: $OUTPUT_DIR/address_differences.txt"
    echo "- Security Analysis: $OUTPUT_DIR/security_analysis.txt"
    echo "- Combined CSV: $OUTPUT_DIR/combined_comparison.csv"
    echo ""
    echo "Quick Statistics:"
    local total_v1=$(grep -c -v "^BINARY," "$RA_FILE_V1" 2>/dev/null || echo "0")
    local total_v2=$(grep -c -v "^BINARY," "$RA_FILE_V2" 2>/dev/null || echo "0")
    echo "- Runtime addresses in Version 1: $total_v1"
    echo "- Runtime addresses in Version 2: $total_v2"
    echo ""
    echo "Next Steps:"
    echo "- Review the security analysis for potential vulnerabilities"
    echo "- Verify ASLR implementation effectiveness"
    echo "- Monitor critical binary changes between versions"
    
} > "$OUTPUT_DIR/summary.txt"

print_output "${GREEN}[+] Summary report created: $OUTPUT_DIR/summary.txt${NC}"
print_output "${GREEN}[+] Runtime Address comparison completed successfully!${NC}"
print_output "${CYAN}[*] All results saved to: $OUTPUT_DIR${NC}"