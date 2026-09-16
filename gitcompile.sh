#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# gitcompile.sh - Remote project compilation via GitHub Actions
# ==============================================================================

# Terminal colors
if [ -t 1 ]; then
  COLOR_GREEN="\033[0;32m"
  COLOR_BLUE="\033[0;34m"
  COLOR_YELLOW="\033[0;33m"
  COLOR_RED="\033[0;31m"
  COLOR_BOLD="\033[1m"
  COLOR_RESET="\033[0m"
else
  COLOR_GREEN=""
  COLOR_BLUE=""
  COLOR_YELLOW=""
  COLOR_RED=""
  COLOR_BOLD=""
  COLOR_RESET=""
fi

log_info() {
  printf "${COLOR_BLUE}${COLOR_BOLD}==>${COLOR_RESET} %s\n" "$1"
}

log_success() {
  printf "${COLOR_GREEN}${COLOR_BOLD}==>${COLOR_RESET} %s\n" "$1"
}

log_warn() {
  printf "${COLOR_YELLOW}${COLOR_BOLD}[!]${COLOR_RESET} %s\n" "$1"
}

log_error() {
  printf "${COLOR_RED}${COLOR_BOLD}[ERROR]${COLOR_RESET} %s\n" "$1" >&2
}

# Ensure ~/.local/bin is in PATH if present
if [ -d "$HOME/.local/bin" ] && [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  export PATH="$HOME/.local/bin:$PATH"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
WORKFLOW_FILE="compile.yml"
ARTIFACT_NAME="traffic-masq-binaries"
OUTPUT_DIR="${SCRIPT_DIR}/binaries"
BUILD_PROFILE="release"
COMMIT_MSG=""
DOWNLOAD_ONLY=false
AUTO_COMMIT=false
NO_COMMIT=false
EPHEMERAL_BRANCH_ACTIVE=false
TARGET_BRANCH=""
RUN_TESTS=false
TESTS_ONLY=false
TEST_FILTER=""
USE_CACHE=true

# CLI usage documentation
usage() {
  echo "Usage: $0 [options] [debug|release] [commit_message]"
  echo ""
  echo "Options:"
  echo "  -n, --no-commit           Compile current working tree (including dirty/uncommitted files)"
  echo "                            via an ephemeral CI branch without creating commits on active branch"
  echo "  -m, --message <text>      Commit uncommitted changes with message before triggering build"
  echo "  -o, --dir <path>          Output directory for binaries (default: ./binaries)"
  echo "  -p, --profile <profile>   Cargo profile: release (default) or debug"
  echo "  -t, --test, --tests       Run test suite on GitHub Actions before building"
  echo "      --test-filter <str>   Run only tests matching pattern (e.g. wifi, config, implies -t)"
  echo "      --test-only           Run tests on GitHub Actions without packaging/downloading binaries"
  echo "      --no-cache            Disable compilation cache on remote runner"
  echo "  -d, --download-only       Download artifacts from the last successful build without compiling"
  echo "  -h, --help                Show this help message"
  echo ""
  echo "Examples:"
  echo "  $0                                   # Compile with cache on active branch"
  echo "  $0 -n                                # Compile dirty uncommitted code without committing"
  echo "  $0 -n -t --test-filter wifi          # Test and compile uncommitted changes without commits"
  echo "  $0 -t                                # Run tests on CI, then build binaries"
  echo "  $0 --test-only                       # Run tests only on CI"
  echo "  $0 \"fix: update configuration\"       # Commit, push, and trigger build"
  echo "  $0 -d                                # Quickly download prebuilt binaries"
  echo "  $0 -o ./my-binaries                  # Save binaries to custom path"
  exit 0
}

# Parse command-line arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--no-commit)
      NO_COMMIT=true
      shift
      ;;
    -m|--message)
      COMMIT_MSG="$2"
      AUTO_COMMIT=true
      shift 2
      ;;
    -o|--dir|--output)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    -p|--profile)
      BUILD_PROFILE="$2"
      shift 2
      ;;
    -t|--test|--tests)
      RUN_TESTS=true
      shift
      ;;
    --test-filter)
      TEST_FILTER="$2"
      RUN_TESTS=true
      shift 2
      ;;
    --test-only|--tests-only)
      RUN_TESTS=true
      TESTS_ONLY=true
      BUILD_PROFILE="debug"
      shift
      ;;
    --no-cache)
      USE_CACHE=false
      shift
      ;;
    -d|--download-only)
      DOWNLOAD_ONLY=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    debug|release)
      BUILD_PROFILE="$1"
      shift
      ;;
    *)
      if [ -z "$COMMIT_MSG" ]; then
        COMMIT_MSG="$1"
        AUTO_COMMIT=true
      fi
      shift
      ;;
  esac
done

# 1. Verify git is available
if ! command -v git >/dev/null 2>&1; then
  log_error "git is not installed or not in PATH."
  exit 1
fi

# 2. Verify gh (GitHub CLI) is available
if ! command -v gh >/dev/null 2>&1; then
  log_error "GitHub CLI (gh) was not found."
  echo "GitHub CLI is required to trigger remote workflows and download build artifacts."
  echo "Install it with:"
  echo "  curl -sL https://github.com/cli/cli/releases/latest/download/gh_linux_amd64.tar.gz | tar -xz && mkdir -p ~/.local/bin && cp gh_*/bin/gh ~/.local/bin/"
  exit 1
fi

# 3. Verify gh authentication
if ! gh auth status >/dev/null 2>&1 && [ -z "${GH_TOKEN:-}" ] && [ -z "${GITHUB_TOKEN:-}" ]; then
  log_warn "You are not authenticated in GitHub CLI."
  echo ""
  echo "GitHub CLI requires authentication to access your repository."
  if [ -t 0 ]; then
    printf "Would you like to run 'gh auth login' now? [Y/n]: "
    read -r response
    case "$response" in
      [nN][oO]|[nN])
        log_error "Authentication cancelled. Please run 'gh auth login' or set GH_TOKEN."
        exit 1
        ;;
      *)
        gh auth login
        ;;
    esac
  else
    log_error "Run 'gh auth login' or export GH_TOKEN=<token>."
    exit 1
  fi
fi

# Artifact download and extraction helper
download_artifacts_for_run() {
  local run_id="$1"
  local target_dir="$2"

  log_info "Downloading build artifacts from run #$run_id into '$target_dir'..."
  mkdir -p "$target_dir"

  local tmp_dir
  tmp_dir=$(mktemp -d)

  # Download artifact archive into temporary directory
  gh run download "$run_id" --name "$ARTIFACT_NAME" --dir "$tmp_dir"

  # Flatten or copy files from temporary directory
  if [ -d "$tmp_dir/$ARTIFACT_NAME" ]; then
    cp -rf "$tmp_dir/$ARTIFACT_NAME"/* "$target_dir"/ 2>/dev/null || true
  else
    cp -rf "$tmp_dir"/* "$target_dir"/ 2>/dev/null || true
  fi
  rm -rf "$tmp_dir"

  # Ensure binaries have execution permissions
  chmod +x "$target_dir"/traffic-masq "$target_dir"/traffic-masqd 2>/dev/null || true

  echo ""
  echo -e "${COLOR_GREEN}${COLOR_BOLD}================================================================${COLOR_RESET}"
  echo -e "${COLOR_GREEN}${COLOR_BOLD}  Binaries successfully compiled and downloaded!${COLOR_RESET}"
  echo -e "  Directory: ${COLOR_BOLD}$target_dir${COLOR_RESET}"
  echo -e "${COLOR_GREEN}${COLOR_BOLD}================================================================${COLOR_RESET}"
  ls -lh "$target_dir" | tail -n +2 | sed 's/^/   /'
  echo ""
  echo -e "To execute:"
  echo -e "  $target_dir/traffic-masq --help"
  echo -e "  $target_dir/traffic-masqd --help"
  echo ""
}

# Ephemeral commit generator: creates a git commit object containing all working tree files
# (including untracked and modified files) without moving HEAD or modifying the git index.
create_ephemeral_commit() {
  local base_ref="${1:-HEAD}"
  local git_dir
  git_dir=$(git rev-parse --git-dir)
  local tmp_index
  tmp_index=$(mktemp)
  if [ -f "$git_dir/index" ]; then
    cp "$git_dir/index" "$tmp_index"
  fi
  GIT_INDEX_FILE="$tmp_index" git add -A
  local tree_id
  tree_id=$(GIT_INDEX_FILE="$tmp_index" git write-tree)
  rm -f "$tmp_index"

  local author_name="${GIT_AUTHOR_NAME:-$(git config user.name 2>/dev/null || echo 'traffic-masq')}"
  local author_email="${GIT_AUTHOR_EMAIL:-$(git config user.email 2>/dev/null || echo 'traffic-masq@local')}"
  local commit_msg="ci: ephemeral snapshot $(date -u +'%Y-%m-%d %H:%M:%S UTC')"

  GIT_AUTHOR_NAME="$author_name" GIT_AUTHOR_EMAIL="$author_email" \
  GIT_COMMITTER_NAME="$author_name" GIT_COMMITTER_EMAIL="$author_email" \
  git commit-tree "$tree_id" -p "$base_ref" -m "$commit_msg"
}

# Cleanup remote temporary branch if an ephemeral build was triggered
cleanup_ephemeral_branch() {
  if [ "${EPHEMERAL_BRANCH_ACTIVE:-false}" = true ] && [ -n "${TARGET_BRANCH:-}" ]; then
    EPHEMERAL_BRANCH_ACTIVE=false
    echo ""
    log_info "Cleaning up remote temporary branch '$TARGET_BRANCH'..."
    git push origin --delete "$TARGET_BRANCH" >/dev/null 2>&1 || true
  fi
}
trap cleanup_ephemeral_branch EXIT INT TERM

# Download-only mode
if [ "$DOWNLOAD_ONLY" = true ]; then
  log_info "Searching for the latest successful build..."
  LATEST_RUN_ID=$(gh run list --workflow="$WORKFLOW_FILE" --status=success --limit 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || true)
  if [ -z "$LATEST_RUN_ID" ]; then
    log_error "No completed successful runs found for workflow '$WORKFLOW_FILE'."
    exit 1
  fi
  download_artifacts_for_run "$LATEST_RUN_ID" "$OUTPUT_DIR"
  exit 0
fi

# Detect current git branch
BRANCH=$(git symbolic-ref --short HEAD 2>/dev/null || true)
if [ -z "$BRANCH" ]; then
  if [ "$NO_COMMIT" = true ]; then
    BRANCH="head"
  else
    log_error "Could not determine current git branch (detached HEAD)."
    exit 1
  fi
fi

log_info "Current git branch: $BRANCH"

# Check for uncommitted working tree changes
UNCOMMITTED=$(git status --porcelain)

if [ "$NO_COMMIT" = true ]; then
  EPHEMERAL_BRANCH_ACTIVE=true
  TARGET_BRANCH="ci-temp-${BRANCH//\//-}"

  if [ -n "$UNCOMMITTED" ]; then
    log_info "No-commit mode: creating ephemeral snapshot from current working tree..."
    COMMIT_TO_BUILD=$(create_ephemeral_commit "HEAD")
  else
    log_info "No-commit mode: working tree clean, using HEAD snapshot..."
    COMMIT_TO_BUILD=$(git rev-parse HEAD)
  fi

  log_info "Pushing snapshot ($COMMIT_TO_BUILD) to remote branch '$TARGET_BRANCH'..."
  git push origin "$COMMIT_TO_BUILD:refs/heads/$TARGET_BRANCH" --force
else
  if [ -n "$UNCOMMITTED" ]; then
    if [ "$AUTO_COMMIT" = true ] && [ -n "$COMMIT_MSG" ]; then
      log_info "Committing local changes: \"$COMMIT_MSG\"..."
      git add -A
      git commit -m "$COMMIT_MSG"
    else
      log_warn "Detected uncommitted changes in the repository:"
      git status --short
      echo ""
      if [ -t 0 ]; then
        echo "Options:"
        echo "  1) Ephemeral build without committing (--no-commit) [recommended]"
        echo "  2) Commit changes to branch '$BRANCH' and push"
        echo "  3) Ignore uncommitted changes (build last pushed commit on '$BRANCH')"
        printf "Choose option [1/2/3, default: 1]: "
        read -r choice
        case "$choice" in
          2)
            printf "Enter commit message (Press Enter for default): "
            read -r user_msg
            msg="${user_msg:-Auto-commit before remote compile}"
            git add -A
            git commit -m "$msg"
            ;;
          3)
            log_warn "Proceeding without committing (GitHub will compile the last pushed commit)."
            ;;
          *)
            NO_COMMIT=true
            EPHEMERAL_BRANCH_ACTIVE=true
            TARGET_BRANCH="ci-temp-${BRANCH//\//-}"
            log_info "No-commit mode: creating ephemeral snapshot from current working tree..."
            COMMIT_TO_BUILD=$(create_ephemeral_commit "HEAD")
            log_info "Pushing snapshot ($COMMIT_TO_BUILD) to remote branch '$TARGET_BRANCH'..."
            git push origin "$COMMIT_TO_BUILD:refs/heads/$TARGET_BRANCH" --force
            ;;
        esac
      else
        log_warn "Non-interactive shell with uncommitted changes: switching to --no-commit ephemeral build."
        NO_COMMIT=true
        EPHEMERAL_BRANCH_ACTIVE=true
        TARGET_BRANCH="ci-temp-${BRANCH//\//-}"
        COMMIT_TO_BUILD=$(create_ephemeral_commit "HEAD")
        git push origin "$COMMIT_TO_BUILD:refs/heads/$TARGET_BRANCH" --force
      fi
    fi
  fi

  if [ "$NO_COMMIT" != true ]; then
    TARGET_BRANCH="$BRANCH"
    log_info "Pushing branch '$BRANCH' to origin..."
    git push origin "$BRANCH"
  fi
fi

# Record the latest run ID before dispatching to track the newly triggered run
PREV_RUN_ID=$(gh run list --workflow="$WORKFLOW_FILE" --limit 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || true)

# Trigger remote workflow on GitHub Actions (with retry in case GitHub is indexing a newly pushed workflow)
if [ "$TESTS_ONLY" = true ]; then
  log_info "Triggering remote test suite on GitHub Actions ($TARGET_BRANCH)..."
else
  log_info "Triggering remote compilation ($BUILD_PROFILE) on GitHub Actions ($TARGET_BRANCH)..."
fi
if [ "$RUN_TESTS" = true ]; then
  if [ -n "$TEST_FILTER" ]; then
    log_info "Remote tests: enabled (filter: '$TEST_FILTER', fast debug mode)"
  else
    log_info "Remote tests: enabled (full suite, fast debug mode)"
  fi
fi
if [ "$USE_CACHE" = true ]; then
  log_info "Remote compilation cache: enabled (Swatinem/rust-cache)"
else
  log_warn "Remote compilation cache: disabled (--no-cache)"
fi

TRIGGERED=false
for attempt in {1..10}; do
  if [ "$attempt" -lt 10 ]; then
    if gh workflow run "$WORKFLOW_FILE" --ref "$TARGET_BRANCH" \
        -f profile="$BUILD_PROFILE" \
        -f run_tests="$RUN_TESTS" \
        -f tests_only="$TESTS_ONLY" \
        -f test_filter="$TEST_FILTER" \
        -f cache="$USE_CACHE" 2>/dev/null; then
      TRIGGERED=true
      break
    fi
  else
    if gh workflow run "$WORKFLOW_FILE" --ref "$TARGET_BRANCH" \
        -f profile="$BUILD_PROFILE" \
        -f run_tests="$RUN_TESTS" \
        -f tests_only="$TESTS_ONLY" \
        -f test_filter="$TEST_FILTER" \
        -f cache="$USE_CACHE"; then
      TRIGGERED=true
      break
    fi
  fi
  sleep 2
done

if [ "$TRIGGERED" != true ]; then
  log_error "Failed to trigger workflow '$WORKFLOW_FILE'. Please ensure it exists on GitHub."
  exit 1
fi

# Wait for GitHub Actions to register the new run
log_info "Waiting for GitHub Actions to register the run..."
RUN_ID=""
for i in {1..30}; do
  sleep 2
  RUN_ID=$(gh run list --workflow="$WORKFLOW_FILE" --branch "$TARGET_BRANCH" --limit 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || true)
  if [ -n "$RUN_ID" ] && [ "$RUN_ID" != "$PREV_RUN_ID" ]; then
    break
  fi
done

if [ -z "$RUN_ID" ] || [ "$RUN_ID" = "$PREV_RUN_ID" ]; then
  log_error "Failed to detect newly queued workflow run on GitHub. Check the Actions tab on GitHub."
  exit 1
fi

RUN_URL=$(gh run view "$RUN_ID" --json url -q .url 2>/dev/null || true)
if [ -n "$RUN_URL" ]; then
  log_info "Workflow run initiated: $RUN_URL"
else
  log_info "Workflow run initiated: Run ID $RUN_ID"
fi

log_info "Streaming build progress in real-time..."
echo ""

# Stream build logs and wait for completion
if ! gh run watch "$RUN_ID" --exit-status; then
  echo ""
  log_error "Remote build failed on GitHub Actions."
  echo "To view failed step logs, run:"
  echo "  gh run view $RUN_ID --log-failed"
  if [ -n "$RUN_URL" ]; then
    echo "Or visit: $RUN_URL"
  fi
  exit 1
fi

if [ "$TESTS_ONLY" = true ]; then
  echo ""
  echo -e "${COLOR_GREEN}${COLOR_BOLD}================================================================${COLOR_RESET}"
  echo -e "${COLOR_GREEN}${COLOR_BOLD}  Remote tests passed successfully on GitHub Actions!${COLOR_RESET}"
  if [ -n "$TEST_FILTER" ]; then
    echo -e "  Filter: ${COLOR_BOLD}$TEST_FILTER${COLOR_RESET}"
  fi
  echo -e "${COLOR_GREEN}${COLOR_BOLD}================================================================${COLOR_RESET}"
  echo ""
  exit 0
fi

# Download compiled binaries
download_artifacts_for_run "$RUN_ID" "$OUTPUT_DIR"
