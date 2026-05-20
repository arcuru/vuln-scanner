You are identifying coverage gaps in a security scan. The initial recon phase
generated a hunt queue, but not every (attack_class × scope) combination was
covered. Your job is to find what was missed and create a second hunt queue
for the gaps.

$environment

## Available Data

Reports have been copied into the `reports/` directory:
- `reports/recon/HUNT_QUEUE.json` — original hunt queue + architecture summary
- `reports/dedupe/FINDINGS.md` — deduplicated findings with coverage gaps section
- `reports/hunt/<task_id>/FINDING.md` — individual hunt results
- Full source code of the repository

Available attack classes: $attack_classes

## Task

1. **Read the deduplication output** — `reports/dedupe/FINDINGS.md` has a
   "Coverage Gaps" section identifying (attack_class × scope) combos suggested
   by the deduplication agent.

2. **Read individual hunt results** — each `reports/hunt/<task_id>/FINDING.md`
   has a "Coverage" section. Aggregate what was and wasn't checked.

3. **Review the original hunt queue** — `reports/recon/HUNT_QUEUE.json` shows
   what was originally assigned. Compare against what was actually completed.

4. **Scan the codebase for unscanned areas** — are there entire files or
   subsystems that weren't touched by any hunt task? Are there high-risk
   patterns (auth logic, crypto, network I/O, file operations) that were
   missed entirely?

5. **Create a gap-filling hunt queue.** Only include tasks that are genuinely
   worth investigating. Don't pad — a small gapfill queue with high-signal
   tasks is better than a large one with noise.

## Output

Write HUNT_QUEUE_2.json in the repo root — same format as the original
HUNT_QUEUE.json:

```json
{
  "architecture_summary": "<same as original, or updated if you discover new context>",
  "generation_note": "<1-2 sentences explaining what gaps this queue fills>",
  "tasks": [
    {
      "id": "<unique kebab-case id>",
      "attack_class": "<from the list above>",
      "scope": "<file path or subsystem name>",
      "function": "<specific function name, or empty if subsystem-wide>",
      "entry_point": "<how attacker input reaches this code>",
      "rationale": "<why this gap matters>"
    }
  ]
}
```

If there are no meaningful gaps, write HUNT_QUEUE_2.json with an empty tasks
array and a generation_note explaining why the initial scan was sufficient.

Write HUNT_QUEUE_2.json and nothing else.