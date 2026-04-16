
- It collects JS file URLs from crawled targets or pre-assembled lists, runs modular static analysis across all collected files concurrently, and optionally submits structured findings to a locally running Llama 3.2 (1B) model via the Ollama API for security interpretation. 

![jsfront](https://github.com/user-attachments/assets/764bbef3-741f-4d19-9ae7-2e09cffb746b)

# Prerequisites

- Python 3.10 or later
- Ollama installed and running locally

The llama3.2:1b model, which JSNinja will attempt to pull automatically via POST /api/pull if not already present.

# Installation

- Clone or download jsninja.py and install the single dependency:

        pip install -r requirements.txt

- No build step, packaging, or PATH modification is required. The script runs directly with python *jsninja.py*.
- To enable AI features, install [Ollama](https://ollama.com/download) and optionally pre-pull the model before the first run:

        ollama pull llama3.2:1b

- The tool will attempt to perform this search automatically if the model is missing when the -a option is invoked, but the pre-search avoids waiting during an active session.

# Usage

        python jsninja.py [-l FILE] [-f FILE] [modules] [-o DIR] [-r] [-a] [options]

- ***-l FILE*** Path to a plain-text file of target base URLs (one per line, http:// or https:// required). JSNinja crawls each URL to collect JS file links.
- ***-f FILE*** Path to a plain-text file of direct JS file URLs. These skip crawling and go straight to the analysis phase. Lines beginning with # are treated as comments and ignored in both input modes.
  
- ***-e*** Extract endpoints
- ***-s*** Detect secrets
- ***-d*** Identify DOM XSS sinks
- ***-v*** Extract JS variable names
- ***-w*** Build a wordlist
- ***-m*** Save JS files locally
- ***-a*** Run local AI analysis
- ***--all*** Activate all of the above plus -r

#### Output and display ####

- ***-o DIR*** Directory where all output files are written. Created recursively if absent. ***Defaults to ./jsninja_output.***
- ***-r*** Generate report.html in the output directory.
- ***--no-banner*** Suppress the startup banner. Useful in scripts or CI pipelines.
- ***--no-color*** Disable ANSI color codes in terminal output.
- ***--verbose*** Set the logging level to DEBUG.

#### Examples ####

- Crawl a list of targets, run all modules, and produce a full report:

        python jsninja.py -l targets.txt --all -o ./results

- Analyse a pre-collected list of JS URLs for secrets and DOM XSS, then request AI interpretation:

        python jsninja.py -f js_urls.txt -s -d -a -r -o ./output
  
- Endpoint and wordlist extraction only, no report:

        python jsninja.py -f js_urls.txt -e -w -o ./output

-  Use the default free model via OpenRouter:

        python jsninja.py -f js_urls.txt -s -a --openrouter --openrouter-key sk-or-v1-... -r -o ./output

- Specify an alternate free model:

        python jsninja.py -f js_urls.txt --all --openrouter --openrouter-model google/gemma-3-27b-it:free -o ./output

- Discover available free models:

        python jsninja.py --openrouter --openrouter-key sk-or-v1-... --list-or-models -o ./output
  

# Disclaimer

- This tool is intended exclusively for use against systems for which the operator holds explicit written authorization. The author accept no liability for unauthorized or unlawful use.
