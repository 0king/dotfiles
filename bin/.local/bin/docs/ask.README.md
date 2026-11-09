# `ask` - Hardened Local AI Filesystem Assistant

`ask` is an ultra-low-latency, sub-2 MB RAM CLI agent powered by **LFM3 1.7B** running in Ollama. It specializes in instant filesystem navigation, code discovery, and technical query answering on resource-constrained hardware (e.g. 4 GB NVIDIA GTX 1050 Ti).

---

## Architecture & Features

- **Runtime**: LuaJIT with `lua-cjson` and `ffi` (starts in ~1.5 ms; negligible memory overhead).
- **LLM Engine**: Ollama serving `lfm3:1.7b-qad-q4_0` by default (or custom `lfm3-agent` built from `Modelfile.lfm3`, with 4096 context window, greedy decoding `temperature 0.0`, ~1.0 GB VRAM).
- **Dynamic Model Selection (`-llm`)**:
  - `-llm <model>` / `--llm <model>` (or `-llm=<model>`): Switch Ollama models on the fly (e.g. `ask -llm lfm3-agent ...` or `ask -llm hadad/LFM2.5-1.2B:Q4_K_M ...`).
  - Automatically persisted across session continuations (`ask -c`).
  - Fallback environment variable: `ASK_MODEL`.
- **Clean Direct Tool Dispatch**:
  - Eliminates brittle Turn 1 keyword pre-grepping that previously poisoned prompt context with red herrings from unrelated files. The model invokes targeted `find_files` or `grep_files` directly with fast, bounded search passes.
- **High-Fidelity Match Discovery & Definition Analysis (`grep_files`)**:
  - Automatically identifies language definition patterns (`alias`, `export`, `function`) across matching lines.
  - Computes exact tallies of unique definition names, active lines, and commented lines (e.g. `[Found 50 unique alias names across 55 active lines (1 commented, 56 total matching lines)]`).
  - Rewrites anchored queries like `^alias` to `^\s*alias` so indented definitions inside conditional or helper blocks are fully captured.
- **Flexible Path & Glob Matching (`find_files`)**:
  - Searches file paths using `fd -H` without full-path glob constraints, enabling natural filename patterns like `*alias*`, `*.zsh`, or `kitty.conf`.
- **Loop Protection & Monologue Suppression**:
  - Normalizes tool call signatures (`seen_sigs`) to detect repeated grep/search loops instantly and break out of redundant turns, eliminating 20–40s hangs down to single-hop completion.
  - Filters internal reasoning and monologue leakages (`is_monologue`) such as "the user asks", "let me search", and "we need to find" from escaping to stdout.
  - Automatically triggers clean text synthesis when tools have finished running, rendering direct, single-paragraph answers in under 1.5 seconds.
- **Directory Scopes & Dash Flags**:
  - `-df` / `--df`: Locks search strictly to `~/dotfiles` (e.g. `ask -df where is starship config?`).
  - `-nn` / `--nn`: Scans personal notes across multi-path arrays (`~/Documents/Notes`, etc.).
  - `-cfg` / `--cfg`: Scans `~/.config`.
  - `-bin` / `--bin`: Scans `~/.local/bin`.
  - Subpath pinning: e.g. `ask -df/zsh where are my aliases?`.
- **Unquoted Queries**: Natural language queries do not require surrounding quotes; Zsh `noglob` alias (`alias ask='noglob ask'`) prevents shell globbing on `?`, `*`, or `[ ]`.
- **Bounded Local Search Tools**:
  - `find_files`: `fd` with `-H` (includes hidden dotfiles) excluding `.git/` and AI skill directories (`~/.config/ai/skills`).
  - `grep_files`: `ripgrep` with `--hidden` excluding `.git/` and AI skills (`!**/ai/skills/**`).
  - `read_file_lines`: Safe line-bounded file inspection (max 80 lines) with access control rejecting attempts to read excluded scopes (e.g. `~/.config/ai/skills`).
- **Optional Ephemeral Flags**:
  - `-fs` / `--find-skills`: Searches AI agent skills in `~/.config/ai/skills` and lifts skill exclusion filters. Can also be scoped directly using subpaths (e.g. `ask -fs/test-driven-development read SKILL.md`).
  - `-w` / `--web` / `--web-search`: Enables DuckDuckGo CLI web search via `ddgr` when external documentation or online facts are required. Disabled by default for strict local containment and trimmed tool schema.
  - `-t` / `--think`: Enables model reasoning / thinking mode (`think: true`) with an expanded 1000-token generation budget and extended curl timeout (240s). Thoughts remain silent and internal, displaying only the final answer. Disabled by default for sub-second responses.
  - `-st` / `--show-thinking`: Automatically enables thinking mode and displays the model's internal stream-of-consciousness reasoning process in dimmed gray text (`\27[90m...\27[0m`) with a clear delimiter before the final answer.
- **Telegraphic Output & Low-Latency Decode**:
  - Configured with `think: false` and telegraphic prompting (`file:line` + setting).
  - Eliminates slow stream-of-consciousness `<thought>` generation that previously burned 9-14 seconds of hidden token generation.
- **Session Continuity**:
  - `ask -c <follow-up>` resumes previous session from `/dev/shm/ask_session_<uid>.json` using Ollama's warm KV cache without re-prefilling past context.
  - Automatically preserves active scope locks and chosen model unless overridden.
- **Interactive Mode**:
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

# 7. Deep thinking / reasoning (complex logic or puzzle)
ask -t how many r's are in strawberry?
ask -t -df explain the execution order of my shell startup scripts

# 8. Visible reasoning process (shows thoughts in dimmed gray text)
ask -st which is larger, 9.9 or 9.11?
ask --show-thinking solve this logic puzzle

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
| **CUDA Dispatch** | `llama-server` worker | Single CPU thread | `num_thread = 1` (Eliminates CPU spinlocks). |
| **Kernel Cgroups** | `systemd/ollama.service` | Hard Host RAM & CPU limits | `CPUQuota=80%`, `MemoryMax=1.6G`, `Nice=19`, `batch`. |

### Systemd Hardware Isolation & Cgroup Configuration

To isolate Ollama to GPU execution and strictly constrain host CPU and RAM utilization, configure the systemd unit drop-in at `/etc/systemd/system/ollama.service.d/override.conf`:

```bash
sudo tee /etc/systemd/system/ollama.service.d/override.conf << 'EOF'
[Service]
# --- GPU & VRAM Offload (100% GPU offload) ---
Environment="OLLAMA_FLASH_ATTENTION=1"
Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
Environment="OLLAMA_KEEP_ALIVE=30m"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_GPU_OVERHEAD=256MiB"

# --- Hard CPU Limits (Never lag the desktop) ---
CPUQuota=80%
Nice=19
CPUSchedulingPolicy=batch

# --- Hard Host RAM Limits ---
MemoryHigh=1200M
MemoryMax=1600M
EOF

sudo systemctl daemon-reload
sudo systemctl restart ollama
```

#### Parameter Breakdown

1. **GPU & VRAM Settings**:
   - `OLLAMA_FLASH_ATTENTION=1`: Enables Flash Attention for hybrid linear/attention operations, optimizing compute directly on CUDA cores.
   - `OLLAMA_KV_CACHE_TYPE=q8_0`: Quantizes the 16k token KV cache to 8-bit in VRAM (~102 MB instead of ~400+ MB), keeping 100% of context memory inside the GPU.
   - `OLLAMA_KEEP_ALIVE=30m`: Keeps the model loaded in VRAM for 30 minutes after queries, enabling instant follow-ups (`ask -c`) without model reload delays.
   - `OLLAMA_MAX_LOADED_MODELS=1` & `OLLAMA_NUM_PARALLEL=1`: Restricts Ollama to one model and one inference stream at a time, preventing VRAM exhaustion or memory spikes on a 4 GB card.
   - `OLLAMA_GPU_OVERHEAD=256MiB`: Preserves a safety margin of VRAM for desktop rendering and prevents Ollama from attempting to allocate beyond physical VRAM limits.

2. **CPU & Threading Constraints**:
   - `CPUQuota=80%`: Linux cgroup v2 hard ceiling. Enforces that Ollama's process group cannot exceed 80% of a single CPU core under any circumstance, leaving all other cores completely free.
   - `Nice=19`: Lowest standard process priority in Linux `SCHED_OTHER`.
   - `CPUSchedulingPolicy=batch`: Instructs the Linux kernel scheduler that Ollama is a non-interactive batch process. Any interactive desktop application, terminal, or browser immediately preempts it.
   - `num_thread = 1` (configured in `ask` payload): Forces `llama-server` to dispatch CUDA commands with only 1 worker thread, preventing multi-core busy-wait spinlocks during CUDA stream synchronization.

3. **System RAM Bounds**:
   - `MemoryHigh=1200M`: Warn/reclaim threshold. Linux kernel aggressively reclaims page cache if Ollama memory usage reaches 1.2 GB.
   - `MemoryMax=1600M`: Hard kernel cgroup ceiling. Prevents memory leaks or runaway buffers from ever exceeding 1.6 GB of host RAM.


