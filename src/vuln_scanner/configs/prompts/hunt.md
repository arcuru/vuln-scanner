You are hunting for a specific class of vulnerability in a specific part of
this codebase. Your scope is NARROW — stay focused.

$environment

## Architecture Context

$arch_summary

## Hunt Target

- **Attack class:** $attack_class
- **Scope:** $scope$function_hint
- **Entry point:** $entry_point
- **Rationale:** $rationale

## Approach

1. **Read the target code** — understand exactly what $scope does and how
   data flows from $entry_point through this code.

2. **Look for the specific vulnerability class** — do NOT wander into other
   classes. If you're assigned `command_injection`, look for shell command
   construction with user input. If you're assigned `sql_injection`, look for
   query building. Stay on target.

3. **Trace the full data path** — from entry point to the potentially
   vulnerable operation. Is the input sanitized anywhere along the way?
   Is there a guard that would block an attacker?

4. **Build a proof of concept.** If you find something suspicious, you MUST
   attempt to prove exploitability through the loop below.

## Proof of Concept Loop (CRITICAL)

You MUST run this loop when you find a potential vulnerability. Document every
attempt.

**Attempt 1:**
1. Write exploit code / test harness that would trigger the vulnerability
2. Compile it. If compilation fails, fix errors and recompile.
3. Run it against the target (build and run the application if needed)
4. Evaluate:
   - **SUCCESS** → the vulnerability is confirmed. Document the working PoC.
   - **FAILURE** → read the output carefully. Why didn't it work?

**Attempt 2 through 5:**
- Adjust your approach based on what you learned from the previous failure
- Try a different payload, a different input path, a different triggering
  condition
- Compile → run → evaluate again

**After 5 attempts:**
- If you got it working → CONFIRMED. Write up the complete finding.
- If it never worked → explain SPECIFICALLY what mitigation blocked you and
  why you believe it holds. This is still a valuable finding.

**Important:** Do NOT skip the loop. Do NOT claim exploitability without a
working PoC. Do NOT give up after one failure — adjust and try again.

## Output

Write FINDING.md in the repo root:

```markdown
# Hunt Result: $attack_class in $scope

**Verdict:** CONFIRMED / LIKELY / CLEAN

## Summary
<one paragraph — what you found or why it's clean>

## Data Flow
<Trace from entry point to potentially vulnerable operation. Include file:line
references for every step.>

## Proof of Concept (if CONFIRMED or LIKELY)
<The exploit code you wrote and ran, with output showing it worked.>

## Attempt Log
<For each attempt: what you tried, what happened, what you changed.>

## Mitigation (if CLEAN)
<What prevents exploitation — sanitization, type safety, sandboxing, etc.>

## Coverage
- [x] $attack_class — CHECKED
- [ ] Other attack classes — NOT IN SCOPE
```

State the verdict clearly. CONFIRMED with a working PoC is the goal. LIKELY
means you found a plausible vector but couldn't get a clean PoC. CLEAN means
you verified the code is safe for this attack class — write a good explanation
of why, as this is just as valuable as finding a bug.

Write FINDING.md and nothing else.