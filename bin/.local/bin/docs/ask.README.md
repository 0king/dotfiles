# `ask` - Hardened Local AI Filesystem Assistant

`ask` is an accurate, technically grounded CLI agent powered by **LFM3 1.7B** running in Ollama. It specializes in verified filesystem navigation, code discovery, and configuration query answering on resource-constrained hardware (e.g. 4 GB NVIDIA GTX 1050 Ti) with thinking mode enabled by default.

---

## Architecture & Features

- **Runtime**: LuaJIT with `lua-cjson` and `ffi` (starts in ~1.5 ms; negligible memory overhead).
- **LLM Engine**: Ollama serving `lfm3:1.7b-qad-q4_0` by default (or custom `lfm3-agent` built from `Modelfile.lfm3`, with 8192 context window, greedy decoding `temperature 0.0`, ~1.25 GB VRAM).
- **Thinking Mode by Default**:
  - Deep internal stream-of-consciousness reasoning (`think: true`) enabled by default to evaluate search plans, verify candidate matches, and inspect surrounding context before producing answers.
  - Silent by default (clean terminal output without raw thought clutter).
  - `-st` / `--show-thinking`: Displays the model's internal stream-of-consciousness reasoning in dimmed gray text (`\27[90m...\27[0m`) with a clear delimiter before the answer.
  - `-nt` / `--no-think`: Opt-out flag for quick, low-latency one-line queries.
  - Configurable via environment: `ASK_THINKING=0` (disable) or `ASK_SHOW_THINKING=1` (always show).
- **Expanded Token & Context Budgets**:
  - Context Window: 8192 tokens by default (`ASK_NUM_CTX=8192`), staying 100% in GPU VRAM (~1.25 GB).
  - Predict Budget: 2048 tokens by default (`ASK_NUM_PREDICT=2048`), ensuring deep reasoning never starves final answers.
  - Full Multi-Paragraph Outputs: Complete answers with code blocks, lists, and multi-file references are preserved in full without artificial truncation.
- **Deepened Multi-Turn Tool Exploration**:
  - Up to 5 investigation turns per query (find -> grep -> read_file_lines -> verify -> conclude).
  - Loop protection: Normalizes tool call signatures (`seen_sigs`) to detect repeated loops and synthesize answers safely.
- **Dynamic Model Selection (`-llm`)**:
  - `-llm <model>` / `--llm <model>` (or `-llm=<model>`): Switch Ollama models on the fly (e.g. `ask -llm lfm3-agent ...` or `ask -llm hadad/LFM2.5-1.2B:Q4_K_M ...`).
  - Automatically persisted across session continuations (`ask -c`).
  - Fallback environment variable: `ASK_MODEL`.
- **High-Fidelity Match Discovery & Definition Analysis (`grep_files`)**:
  - Automatically identifies language definition patterns (`alias`, `export`, `function`) across matching lines.
  - Computes exact tallies of unique definition names, active lines, and commented lines (e.g. `[Found 50 unique alias names across 55 active lines (1 commented, 56 total matching lines)]`).
  - Rewrites anchored queries like `^alias` to `^\s*alias` so indented definitions inside conditional or helper blocks are fully captured.
  - Returns up to 150 matching lines with 500-column preview.
- **Flexible Path & Glob Matching (`find_files`)**:
  - Searches file paths using `fd -H` without full-path glob constraints, enabling natural filename patterns like `*alias*`, `*.zsh`, or `kitty.conf`.
  - Returns up to 120 matching results.
- **Deep File Inspection (`read_file_lines`)**:
  - Reads up to 200 lines per call with up to 1000 characters per line, allowing full function or block inspection.
- **Directory Scopes & Dash Flags**:
  - `-df` / `--df`: Locks search strictly to `~/dotfiles` (e.g. `ask -df where is starship config?`).
  - `-nn` / `--nn`: Scans personal notes across multi-path arrays (`~/Documents/Notes`, etc.).
  - `-cfg` / `--cfg`: Scans `~/.config`.
  - `-bin` / `--bin`: Scans `~/.local/bin`.
  - Subpath pinning: e.g. `ask -df/zsh where are my aliases?`.
- **Unquoted Queries**: Natural language queries do not require surrounding quotes; Zsh `noglob` alias (`alias ask='noglob ask'`) prevents shell globbing on `?`, `*`, or `[ ]`.
- **Optional Ephemeral Flags**:
  - `-fs` / `--find-skills`: Searches AI agent skills in `~/.config/ai/skills` and lifts skill exclusion filters. Can also be scoped directly using subpaths (e.g. `ask -fs/test-driven-development read SKILL.md`).
  - `-w` / `--web` / `--web-search`: Enables DuckDuckGo CLI web search via `ddgr` when external documentation or online facts are required. Disabled by default for strict local containment.
- **Session Continuity & Interactive Mode**:
  - `ask -c <follow-up>` resumes previous session from `/dev/shm/ask_session_<uid>.json` using Ollama's warm KV cache without re-prefilling past context.
  - `ask -i [query]` drops into a persistent multi-turn prompt.

---

## Usage Examples

```bash
# 1. Unquoted general priority search (speculative zero-hop)
ask where is my shell prompt configured?

# 2. Scope-pinned queries (single dash, double dash, or subpaths)
ask -df where are my zsh aliases?
ask --df where are my zsh aliases?
ask -df/kitty show my keybindings

# 3. Dynamic model switching (-llm / --llm)
ask -llm lfm3-agent -df where are my zsh aliases?
ask -llm hadad/LFM2.5-1.2B:Q4_K_M what is my default shell?

# 4. Multi-path notes search
ask -nn what notes do I have on project architecture?

# 5. AI Skills search & inspection (-fs / --find-skills)
ask -fs what skills are available for code review?
ask -fs find test-driven-development skill
ask -fs/test-driven-development read the first 10 lines of SKILL.md

# 6. Web search (external documentation)
ask -w what are the latest features in Lua 5.4?

# 7. Accurate reasoning with verified context (thinking mode enabled by default)
ask how many r's are in strawberry?
ask -df explain how my zsh configuration is structured

# 8. Visible reasoning process (shows dimmed thoughts before answer)
ask -st which is larger, 9.9 or 9.11?
ask --show-thinking -df what are the keybindings in kitty?

# 9. Low-latency one-liner (opt-out of thinking)
ask -nt -df quick check for tmux prefix

# 9. Zero-cold-start follow-up
ask -c what is the font size set right below that?

# 10. Interactive session
ask -i
```

---

## Configuration & Stow Integration

Managed in `~/dotfiles` under GNU Stow:
- Binary: `~/dotfiles/bin/.local/bin/ask` -> symlinked to `~/.local/bin/ask`
- Aliases: `~/dotfiles/zsh/.config/zsh/aliases.zsh` -> `alias ask='noglob ask'`
- Stowed via: `dotfiles apply`

---

## Resource Footprint & GPU Sandboxing

| Layer | Component | Hardware Allocation | Constraints |
| --- | --- | --- | --- |
| **Model Weights** | `lfm3:1.7b` (`Q4_K_M`) | **100% GPU VRAM** (~1.1 GB) | `num_gpu = 999` (Zero CPU fallback). |
| **KV Cache** | 16k context window (`q8_0`) | **100% GPU VRAM** (~102 MB) | `OLLAMA_KV_CACHE_TYPE=q8_0` (Zero RAM allocation). |
| **CUDA Dispatch** | `llama-server` worker | 2 CPU threads | `num_thread = 2` (Low-latency CUDA dispatch, no driver lock starvation). |
| **Kernel Cgroups** | `systemd/ollama.service` | Host RAM bounds & priority safety | `Nice=10`, `MemoryHigh=2500M`, `MemoryMax=3000M`. |

### Systemd Hardware Isolation & Cgroup Configuration

To isolate Ollama to GPU execution, prevent CFS priority inversions against Wayland/GNOME Shell, and constrain host RAM utilization, configure the systemd unit drop-in at `/etc/systemd/system/ollama.service.d/override.conf`:

```bash
sudo tee /etc/systemd/system/ollama.service.d/override.conf << 'EOF'
[Service]
# --- GPU & VRAM Offload (100% GPU offload on GTX 1050 Ti) ---
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
Environment="OLLAMA_KEEP_ALIVE=30m"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_GPU_OVERHEAD=268435456"

# --- CPU Scheduling (Low-latency CUDA dispatch, no driver lock starvation) ---
Nice=10

# --- Host RAM Bounds (Prevent swap thrashing) ---
MemoryHigh=2500M
MemoryMax=3000M
EOF

sudo systemctl daemon-reload
sudo systemctl restart ollama
```

#### Parameter Breakdown

1. **GPU & VRAM Settings**:
   - `OLLAMA_FLASH_ATTENTION=1`: Enables Flash Attention for hybrid linear/attention operations and enables 8-bit quantized KV cache (`q8_0`).
   - `OLLAMA_KV_CACHE_TYPE=q8_0`: Quantizes the 16k token KV cache to 8-bit in VRAM (~102 MB instead of ~400+ MB), keeping 100% of context memory inside the GPU.
   - `OLLAMA_KEEP_ALIVE=30m`: Keeps the model loaded in VRAM for 30 minutes after queries, enabling instant follow-ups (`ask -c`) without model reload delays.
   - `OLLAMA_MAX_LOADED_MODELS=1` & `OLLAMA_NUM_PARALLEL=1`: Restricts Ollama to one model and one inference stream at a time, preventing VRAM exhaustion or memory spikes on a 4 GB card.
   - `OLLAMA_GPU_OVERHEAD=268435456`: Preserves 256 MiB safety margin of VRAM for desktop rendering and Wayland/GNOME Shell compositor surfaces (in bytes integer syntax recognized by Ollama).

2. **CPU & Threading Constraints**:
   - `Nice=10`: Lowers Ollama's process priority relative to interactive desktop apps without using `SCHED_BATCH` or `CPUQuota=80%`, preventing CFS priority inversions against NVIDIA kernel driver locks (`nvidia.ko`).
   - `num_thread = 2` (configured in `ask` payload): Dispatches CUDA commands and processes prompt tokens efficiently without monopolizing the 12 CPU cores.

3. **System RAM Bounds**:
   - `MemoryHigh=2500M`: Warn/reclaim threshold. Prevents aggressive direct page reclaim loops while providing ample room for prompt caches and CUDA pinned buffers.
   - `MemoryMax=3000M`: Hard kernel cgroup ceiling. Prevents runaway leaks from exceeding 3 GB of host RAM while eliminating swap thrashing.

---

### Why the Legacy Cgroup Configuration Was Self-Defeating

Earlier configurations attempted to protect desktop responsiveness using aggressive CPU quotas and strict memory ceilings (`CPUQuota=80%`, `Nice=19`, `CPUSchedulingPolicy=batch`, `MemoryHigh=1200M`). While well-intentioned, these limits caused severe system freezes through four counter-productive failure modes:

1. **CFS Priority Inversion Against GNOME Shell (The Primary Freeze Trigger)**:
   - On Linux with NVIDIA Optimus/Wayland, GNOME Shell (Mutter) coordinates display surfaces with the NVIDIA kernel driver (`nvidia.ko`).
   - Capping Ollama to `CPUQuota=80%` with `SCHED_BATCH` caused the Linux CFS scheduler to hard-throttle Ollama 75.6% of the time.
   - When Ollama was suspended by CFS mid-inference while holding GPU channels or driver synchronization mutexes, GNOME Shell's compositor blocked in kernel space waiting for the lock, freezing the mouse, display, and keyboard input.

2. **Synchronous Memory Reclaim & Swap Thrashing**:
   - `llama-server` context buffers and CUDA driver pinned host memory require ~1.5–2.0 GB of host RAM.
   - Capping memory at `MemoryHigh=1200M` was breached thousands of times, forcing the kernel into synchronous direct page reclaim and swapping 182 MB of active buffers to disk, stalling system I/O.

3. **Single-Thread Dispatch Bottleneck (`num_thread = 1`)**:
   - Restricting CPU dispatch to a single thread under-utilized the 12-thread CPU and serialized prompt tokenization and CUDA stream synchronization, dragging throughput down to 5.3 tokens/second.

4. **Rejected GPU Overhead Syntax (`256MiB`)**:
   - Ollama requires overhead in raw byte integers (`268435456`). Passing `256MiB` caused Ollama to log a warning and silently fall back to `0 B`, leaving zero VRAM safety headroom for desktop rendering surfaces.



