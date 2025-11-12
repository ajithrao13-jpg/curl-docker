#!/bin/bash
#
# Build and Security Scan Script for Liquibase Docker Images
# This script builds different variants and scans them for vulnerabilities
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
IMAGE_NAME="liquibase-azure"
REGISTRY="${DOCKER_REGISTRY:-localhost}"

# Functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    if ! command -v docker scout &> /dev/null; then
        log_warning "Docker Scout CLI not found. Install with: docker scout install"
    fi
    
    log_success "Prerequisites check completed"
}

# Build original image
build_original() {
    log_info "Building original image..."
    docker build -t ${IMAGE_NAME}:original -f Dockerfile .
    log_success "Original image built: ${IMAGE_NAME}:original"
}

# Build secure image
build_secure() {
    log_info "Building secure image..."
    docker build -t ${IMAGE_NAME}:secure -f Dockerfile.secure .
    log_success "Secure image built: ${IMAGE_NAME}:secure"
}

# Build distroless image
build_distroless() {
    log_info "Building distroless image..."
    docker build -t ${IMAGE_NAME}:distroless -f Dockerfile.distroless .
    log_success "Distroless image built: ${IMAGE_NAME}:distroless"
}

# Scan image for vulnerabilities
scan_image() {
    local tag=$1
    local image="${IMAGE_NAME}:${tag}"
    
    log_info "Scanning ${image} for vulnerabilities..."
    
    # Create output directory
    mkdir -p scan-results
    
    # Docker Scout scan
    if command -v docker scout &> /dev/null; then
        log_info "Running Docker Scout scan..."
        docker scout cves ${image} --format markdown > scan-results/${tag}-scout.md
        docker scout cves ${image} --format sarif > scan-results/${tag}-scout.sarif
        
        # Get vulnerability summary
        docker scout cves ${image} --only-severities critical,high > scan-results/${tag}-critical-high.txt
        
        log_success "Docker Scout scan completed for ${tag}"
    else
        log_warning "Docker Scout not available, skipping Scout scan"
    fi
    
    # Trivy scan (if available)
    if command -v trivy &> /dev/null; then
        log_info "Running Trivy scan..."
        trivy image --format json --output scan-results/${tag}-trivy.json ${image}
        trivy image --severity HIGH,CRITICAL ${image} > scan-results/${tag}-trivy.txt
        log_success "Trivy scan completed for ${tag}"
    else
        log_warning "Trivy not available, skipping Trivy scan"
    fi
}

# Test image functionality
test_image() {
    local tag=$1
    local image="${IMAGE_NAME}:${tag}"
    
    log_info "Testing ${image} functionality..."
    
    # Test version
    if docker run --rm ${image} --version; then
        log_success "Version check passed"
    else
        log_error "Version check failed"
        return 1
    fi
    
    # Test help
    if docker run --rm ${image} --help > /dev/null 2>&1; then
        log_success "Help command passed"
    else
        log_error "Help command failed"
        return 1
    fi
    
    log_success "Functional tests passed for ${image}"
}

# Compare vulnerability counts
compare_images() {
    log_info "Comparing vulnerability counts..."
    
    echo ""
    echo "==================================="
    echo "  VULNERABILITY COMPARISON REPORT"
    echo "==================================="
    echo ""
    
    for tag in original secure distroless; do
        if docker images ${IMAGE_NAME}:${tag} -q > /dev/null 2>&1; then
            echo "--- ${IMAGE_NAME}:${tag} ---"
            
            if command -v docker scout &> /dev/null; then
                # Use Docker Scout for comparison
                docker scout cves ${IMAGE_NAME}:${tag} --format json 2>/dev/null | \
                    jq -r '.vulnerabilities | group_by(.severity) | map({severity: .[0].severity, count: length}) | .[] | "\(.severity): \(.count)"' || \
                    echo "Unable to parse vulnerability data"
            fi
            
            # Image size
            size=$(docker images ${IMAGE_NAME}:${tag} --format "{{.Size}}")
            echo "Size: ${size}"
            echo ""
        fi
    done
}

# Generate summary report
generate_report() {
    log_info "Generating summary report..."
    
    cat > scan-results/SUMMARY.md <<EOF
# Security Scan Summary

Generated: $(date)

## Images Scanned

$(docker images ${IMAGE_NAME} --format "| {{.Tag}} | {{.Size}} | {{.ID}} |")

## Vulnerability Breakdown

### Original Image
- See: scan-results/original-scout.md
- Critical/High: scan-results/original-critical-high.txt

### Secure Image  
- See: scan-results/secure-scout.md
- Critical/High: scan-results/secure-critical-high.txt

### Distroless Image
- See: scan-results/distroless-scout.md  
- Critical/High: scan-results/distroless-critical-high.txt

## Recommendations

1. Review VULNERABILITY_FIXES.md for detailed analysis
2. Review SECURITY_RECOMMENDATIONS.md for implementation guidance
3. Choose appropriate image variant based on security/functionality tradeoffs
4. Integrate vulnerability scanning into CI/CD pipeline

## Next Steps

- [ ] Review scan results
- [ ] Choose image variant (secure or distroless recommended)
- [ ] Update deployment configurations
- [ ] Set up automated scanning
- [ ] Document accepted risks

EOF
    
    log_success "Summary report generated: scan-results/SUMMARY.md"
}

# Main menu
show_menu() {
    echo ""
    echo "=================================="
    echo "  Liquibase Security Build Tool"
    echo "=================================="
    echo ""
    echo "1) Build all images"
    echo "2) Build original image only"
    echo "3) Build secure image only"
    echo "4) Build distroless image only"
    echo "5) Scan all images"
    echo "6) Scan specific image"
    echo "7) Test all images"
    echo "8) Test specific image"
    echo "9) Compare images"
    echo "10) Generate full report"
    echo "11) Clean up images"
    echo "0) Exit"
    echo ""
}

# Clean up function
cleanup() {
    log_info "Cleaning up images..."
    docker rmi ${IMAGE_NAME}:original ${IMAGE_NAME}:secure ${IMAGE_NAME}:distroless 2>/dev/null || true
    log_success "Cleanup completed"
}

# Main execution
main() {
    check_prerequisites
    
    if [ $# -eq 0 ]; then
        # Interactive mode
        while true; do
            show_menu
            read -p "Select an option: " choice
            
            case $choice in
                1)
                    build_original
                    build_secure
                    build_distroless
                    ;;
                2)
                    build_original
                    ;;
                3)
                    build_secure
                    ;;
                4)
                    build_distroless
                    ;;
                5)
                    for tag in original secure distroless; do
                        if docker images ${IMAGE_NAME}:${tag} -q > /dev/null 2>&1; then
                            scan_image ${tag}
                        fi
                    done
                    ;;
                6)
                    read -p "Enter image tag (original/secure/distroless): " tag
                    scan_image ${tag}
                    ;;
                7)
                    for tag in original secure distroless; do
                        if docker images ${IMAGE_NAME}:${tag} -q > /dev/null 2>&1; then
                            test_image ${tag}
                        fi
                    done
                    ;;
                8)
                    read -p "Enter image tag (original/secure/distroless): " tag
                    test_image ${tag}
                    ;;
                9)
                    compare_images
                    ;;
                10)
                    build_original
                    build_secure
                    build_distroless
                    for tag in original secure distroless; do
                        scan_image ${tag}
                        test_image ${tag}
                    done
                    compare_images
                    generate_report
                    log_success "Full report completed! Check scan-results/ directory"
                    ;;
                11)
                    cleanup
                    ;;
                0)
                    log_info "Exiting..."
                    exit 0
                    ;;
                *)
                    log_error "Invalid option"
                    ;;
            esac
        done
    else
        # Command-line mode
        case "$1" in
            build)
                build_original
                build_secure
                build_distroless
                ;;
            scan)
                for tag in original secure distroless; do
                    scan_image ${tag}
                done
                ;;
            test)
                for tag in original secure distroless; do
                    test_image ${tag}
                done
                ;;
            report)
                build_original
                build_secure
                build_distroless
                for tag in original secure distroless; do
                    scan_image ${tag}
                    test_image ${tag}
                done
                compare_images
                generate_report
                ;;
            clean)
                cleanup
                ;;
            *)
                echo "Usage: $0 [build|scan|test|report|clean]"
                echo "Run without arguments for interactive mode"
                exit 1
                ;;
        esac
    fi
}

# Run main function
main "$@"
